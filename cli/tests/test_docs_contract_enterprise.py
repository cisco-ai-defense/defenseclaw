# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Docs contract: enterprise, sandbox and lifecycle facts the rewritten docs must keep.

These checks replace the exact-phrase tests that lived in
docs-site/scripts/test_r10*_docs.py, which pinned the old page layout and no
longer matched any page. Each entry names the page that now holds the fact; a
phrase is checked after whitespace is collapsed. When a page is reworded or
split, repoint the entry. Do not drop it unless the product behavior it
protects is gone.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def _flat(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


def test_managed_hook_docs_distinguish_outages_from_refusals() -> None:
    threat_model = (ROOT / "docs/ENTERPRISE-THREAT-MODEL.md").read_text(encoding="utf-8")
    rate_limit = next(line for line in threat_model.splitlines() if line.startswith("| R31 |"))
    coverage = _flat("appendix/coverage-by-layer.mdx")
    for text in (rate_limit, coverage):
        assert not re.search(r"always fails?[ -]closed", text, re.IGNORECASE)
        assert all(term in text for term in ("default", "closed", "administrator", "open", "outage", "Secure Client"))
        assert all(term in text for term in ("runtime", "peer", "credential"))
    assert "429" in rate_limit and "block" in rate_limit
    assert "outage-only" in rate_limit and "outage-only" in coverage

    fail_modes = _flat("reference/configuration/fail-modes.mdx")
    # guard GAP-0782: the closed-posture section replaces the strict-availability one.
    strict = fail_modes.split("## Set a closed posture", 1)[1].split("## ", 1)[0]
    assert "classified outages" in strict
    assert "force the unavailable-home and transport failures closed" not in strict
    assert "force the relevant unavailable-home and transport failures closed" not in strict

    guidance = (
        _flat("enterprise/plan/threat-model.mdx").split("### Disable hooks", 1)[1].split("### ", 1)[0],
        _flat("enterprise/configure/reference.mdx").split("### Hook commands by route", 1)[1].split("## ", 1)[0],
        _flat("enterprise/operate/lifecycle.mdx").split("## Restart the managed gateway", 1)[1].split("## ", 1)[0],
        _flat("enterprise/operate/reference.mdx")
        .split("### Gateway restarts and hook timing", 1)[1].split("### ", 1)[0],
    )
    for text in guidance:
        assert not re.search(r"always fails?[ -]closed|never allows a call because", text, re.IGNORECASE)
        assert "hook_fail_mode: open" in text and "outage" in text

    troubleshooting = (DOCS / "troubleshooting/enterprise/index.mdx").read_text(encoding="utf-8")
    for reason in ("enterprise_managed_rate_limited", "enterprise_managed_overloaded"):
        row = next(line for line in troubleshooting.splitlines() if line.startswith(f"| `{reason}` |"))
        assert "not a classified" in row and "block" in row
        assert "always fails closed" not in row



def test_managed_outage_open_docs_name_rate_limits_and_the_guard_session_check() -> None:
    """Rate limits block after the resends; guarded outage calls need trusted
    process and session records even when the administrator selects open."""
    threat_model = (ROOT / "docs/ENTERPRISE-THREAT-MODEL.md").read_text(encoding="utf-8")
    r31 = next(line for line in threat_model.splitlines() if line.startswith("| R31 |"))
    assert "including for Claude Code, Codex and Devin" not in r31
    assert "If no verdict follows" in r31 and "every fail mode" in r31
    for name in ("Cursor", "GitHub Copilot", "Devin", "OpenCode", "Amp", "Hermes", "managed_hooks_only: preserve"):
        assert name in r31

    coverage = _flat("appendix/coverage-by-layer.mdx")
    guarded = (
        r31,
        coverage.split("Secure Client keeps its separate open default", 1)[0],
        _flat("enterprise/configure/reference.mdx").split("### Hook commands by route", 1)[1].split("## ", 1)[0],
        _flat("reference/configuration/fail-modes.mdx").split("## Effective behavior", 1)[0],
        _flat("enterprise/operate/lifecycle.mdx").split("## Restart the managed gateway", 1)[1].split("## ", 1)[0],
        _flat("enterprise/operate/reference.mdx")
        .split("### Gateway restarts and hook timing", 1)[1].split("### ", 1)[0],
        _flat("enterprise/plan/threat-model.mdx").split("### Disable hooks", 1)[1].split("### ", 1)[0],
    )
    for text in guarded:
        assert "foreign_hooks: remove" in text

    per_layer = coverage.split("## Fail-open and fail-closed, per layer", 1)[1].split("## ", 1)[0]
    assert "in observe mode | Open" not in per_layer
    assert "Managed Claude Code and Codex hooks | Always closed" not in per_layer
    assert "observe and action mode alike" in per_layer and "outage only" in per_layer
    assert re.search(r"foreign_hooks: remove.*agent process.*session.*15 minutes", per_layer)
    assert "not for a connector whose foreign-hook guard checks the session" not in per_layer
    assert "observe mode fails open" not in coverage

    troubleshooting = (DOCS / "troubleshooting/enterprise/index.mdx").read_text(encoding="utf-8")
    for reason in ("enterprise_managed_rate_limited", "enterprise_managed_overloaded"):
        row = next(line for line in troubleshooting.splitlines() if line.startswith(f"| `{reason}` |"))
        assert "resends" in row and "if no verdict follows" in row
    no_answer = next(
        line for line in troubleshooting.splitlines() if line.startswith("| `enterprise_managed_gateway_no_answer` |")
    )
    assert "HTTP 429" in no_answer and "foreign_hooks: remove" in no_answer


# (fact, [(pages that may hold the phrase, phrase), ...])
FACTS = [
    ('scanner_tree_names_the_linux_custodian_escape_limit', [
        (('reference/scanning/scanners.mdx',),
         'On Linux, if a scanner SIGKILLs its child-subreaper custodian, a detached child can keep running even though the scan fails closed.'),
    ]),
    ('scanner_tree_names_the_macos_escape_limit', [
        (('reference/scanning/scanners.mdx',),
         "macOS has one known limit: a child that forks, starts a new session and exits between two reads of the process table (about 100 ms apart) can hand its own child to launchd before the gateway sees it. If that child keeps a descriptor it inherited, the scan fails closed; if it closes every descriptor, it is not found and keeps running."),
    ]),
    ('account_outage_refusal_matches_the_cli', [
        (('enterprise/runtime/sandbox-reference.mdx',),
         "This isn't your organization's sandbox policy."),
        (('enterprise/runtime/sandbox-reference.mdx',),
         'If a profile assignment needs the unanswered identity fact, the create and hooks are refused with that fact named.'),
    ]),
    ('managed_start_session_rule_row', [
        (('troubleshooting/sandboxes/runs-and-sessions.mdx',),
         'approved for its last session, could not be removed from its policy'),
        (('troubleshooting/sandboxes/runs-and-sessions.mdx',),
         'is still running with the network rule <rule> approved for its last session'),
    ]),
    ('troubleshooting_explains_the_api_level_mtls_check', [
        (('troubleshooting/sandboxes/setup-and-gateway.mdx',),
         "DefenseClaw checks that the gateway lets a client without a certificate finish the TLS handshake but refuses that client's API calls, and that the gateway has no OIDC issuer."),
    ]),
    ('gap_0012_admission_profile_roots', [
        (('reference/scanning/admission.mdx',),
         'assets there do not receive its install-admission scan'),
        (('reference/scanning/admission.mdx',),
         'Explicit `gateway.watcher.skill.dirs` prevent project folders from being added on every platform'),
    ]),
    ('gap_0957_managed_windows_profile_runtime_rules', [
        (('reference/scanning/admission.mdx',),
         'MCP runtime detection defaults to true'),
        (('reference/scanning/admission.mdx',),
         'Set `asset_policy.enabled: true` as well'),
    ]),
    ('gap_0012_denied_config_rechecks_watched_roots_only', [
        (('reference/scanning/admission.mdx',),
         'For watched roots (per-user installs and managed Windows roots outside profiles)'),
        (('reference/scanning/admission.mdx',),
         'Managed Windows profile assets and managed Linux/macOS connector assets are refused only by the hooks'),
    ]),
    ('gap_0012_skill_watcher_profile_roots', [
        (('reference/scanning/scanners.mdx',),
         'skills there receive no watcher scan'),
        (('reference/scanning/admission.mdx', 'reference/scanning/scanners.mdx'),
         'scan a copy outside profiles'),
    ]),
    ('gap_0012_mcp_watcher_profile_roots', [
        (('reference/scanning/scanners.mdx',),
         'receive the install-watcher scan: the scanner runs in the gateway service and the hook enumerator starts each server as its user'),
    ]),
    ('gap_0554_enterprise_linux_docker_limit', [
        (('enterprise/install/reference/linux.mdx',),
         'must not give them Docker access'),
        (('enterprise/install/reference/linux.mdx',),
         'root-owned image and lifecycle service'),
    ]),
    ('gap_0445_cli_unreadable_sandbox_list', [
        (('reference/commands/cli.mdx',),
         'Only `stopped`, `completed`, `deleted` and `missing` do not'),
        (('reference/commands/cli.mdx',),
         '`error`, `stopping`, `creating` and `deleting` phases count as running'),
    ]),
    ('gap_0226_windows_install_discovery', [
        (('enterprise/configure/reference.mdx',),
         'official Codex `install.ps1` layout'),
        (('enterprise/configure/reference.mdx',),
         'per-user WinGet packages for signed-in users'),
    ]),
    ('gap_0255_profile_explain_account_ids', [
        (('reference/policy/guardrail-profiles.mdx',),
         'Group assignments follow the OS-verified account ID'),
        (('reference/policy/guardrail-profiles.mdx',),
         'use each uid or SID with `guardrail profile explain --user`'),
    ]),
    ('gap_0528_macos_bare_group_name_selects_local_and_domain_group', [
        (('reference/policy/guardrail-profiles.mdx',),
         'selects the members of that local group'),
        (('reference/policy/guardrail-profiles.mdx',),
         'A bare name also selects, by its name part,'),
    ]),
    ('gap_0595_matched_group_source_lists_every_value', [
        (('reference/policy/guardrail-profiles.mdx',),
         '`matched_group_source` (`local`, `directory` or `local and directory`)'),
        (('reference/policy/guardrail-profiles.mdx',),
         'If the source cannot be determined, `matched_group_source` is left out'),
    ]),
    ('no_sandbox_registry_names_both_host_run_exceptions', [
        (('reference/configuration/env-vars.mdx',),
         'host run is still refused unless the account is in `enterprise.enrollment.exempt_users`, or sandboxes are unavailable to the account and the effective `when_unavailable` setting is `alert`'),
    ]),
    ('no_sandbox_generated_env_vars_row_names_both_exceptions', [
        (('reference/configuration/env-vars.mdx',),
         'host run is still refused unless the account is in `enterprise.enrollment.exempt_users`, or sandboxes are unavailable to the account and the effective `when_unavailable` setting is `alert`'),
    ]),
    ('gap_0534_macos_users_entry_names_the_upn', [
        (('reference/policy/guardrail-profiles.mdx',),
         "and by its UPN, which the hook guardian reads from the account's domain record (a mobile account's included)"),
    ]),
    ('gap_1356_windows_project_skill_roots_skipped', [
        (('enterprise/install/reference/windows.mdx',),
         'project skill folders inside profiles are skipped before verification or registration'),
        (('enterprise/install/reference/windows.mdx',),
         'no install scan, no "is not scanned yet" refusal and no `project_skill_root_unverified` warning'),
    ]),
    ('gap_0289_invalid_machine_policy_is_config_invalid', [
        (('troubleshooting/enterprise/index.mdx',),
         'Invalid `enterprise.machine_policy` settings fail validation as `config_invalid`'),
    ]),
    ('gap_0292_linux_fips_support', [
        (('enterprise/install/reference/linux.mdx',),
         '| FIPS mode | RHEL 9 in FIPS mode is supported'),
    ]),
    ('gap_0294_purge_removes_lifecycle_lock', [
        (('enterprise/install/reference/windows.mdx',),
         'The Secure Client profile keeps the lock unless `PURGE=1`'),
        (('enterprise/install/reference/windows.mdx',),
         'A standalone Setup uninstall removes the administrator-only'),
    ]),
    ('gap_0303_jsonl_collection_requires_read_access', [
        (('enterprise/operate/reference.mdx',),
         'file is `0600` inside a service-owned `0750` folder'),
        (('enterprise/operate/reference.mdx',),
         'only if it runs as root or the `defenseclaw` service account'),
    ]),
    ('gap_0304_managed_audit_pipe_has_consistent_ownership', [
        (('enterprise/identity/ad-linux.mdx',),
         'audit export --since 10m \\ | jq -c'),
    ]),
    ('gap_0345_projected_principal_values', [
        (('enterprise/identity/reference.mdx',),
         'and `kerberos_principal` values are `null`'),
    ]),
    ('gap_0306_never_signed_in_lookup_is_host_specific', [
        (('enterprise/identity/reference.mdx',),
         'may resolve an Entra name or UPN to a SID before first sign-in'),
    ]),
    ('deprecated_enterprise_example_omits_omnigent_image', [
        (('enterprise/runtime/sandbox-reference.mdx',),
         'Claude Code, Codex, Copilot and Cursor images'),
    ]),
    ('gap_0319_host_refusal_reason_is_required_for', [
        (('enterprise/runtime/sandbox-reference.mdx',),
         '| `required_for` | Not a failure.'),
    ]),
    ('fg01_absent_connector_cleanup', [
        (('reference/commands/cli.mdx',),
         'the command removes DefenseClaw hook entries it left'),
    ]),
    ('fg05_active_metric_refresh', [
        (('reference/sandboxes/telemetry.mdx',),
         'Exported every minute, including `0`'),
        (('reference/sandboxes/telemetry.mdx',),
         'a running sandbox counts again within a minute'),
    ]),
    ('fg07_macos_app_stop_full_disk', [
        (('reference/commands/tui.mdx',),
         'full-disk MicroVM with work not yet pulled keeps running'),
    ]),
    ('fg11_windows_secret_remove_checks_config', [
        (('enterprise/configure/reference.mdx',),
         'leaves the credential in place'),
        (('enterprise/configure/reference.mdx',),
         'If it cannot read that config, it refuses'),
    ]),
    ('fg12_package_uninstall_refusal', [
        (('enterprise/operate/reference.mdx',),
         '`uninstall_incomplete` keeps the package files'),
    ]),
    ('fg12_duplicate_rpm_repair', [
        (('enterprise/operate/reference.mdx',),
         'does not repair the package database'),
        (('enterprise/operate/reference.mdx',),
         '`sudo dnf remove --duplicates defenseclaw-enterprise`'),
    ]),
    ('fg12_infopipe_upn_expiry', [
        (('enterprise/identity/sources.mdx',),
         'kept for at most 24 hours (`upn_source: infopipe_kept`)'),
    ]),
    ('fg12_local_groups_follow_nsswitch', [
        (('enterprise/identity/sources.mdx',),
         'only when `nsswitch.conf` lists `files` or `compat`'),
    ]),
    ('fg13_intune_rollback_assignment', [
        (('enterprise/operate/lifecycle.mdx',),
         'remove the superseding **Required** assignment'),
    ]),
    ('lfuninst_cli_running_sandbox_option', [
        (('reference/commands/cli.mdx',),
         '`reset` takes this option too'),
        (('reference/commands/cli.mdx',),
         '| `defenseclaw uninstall --stop-sandboxes` |'),
    ]),
    ('pr886_api_key_rule_list', [
        (('reference/configuration/index.mdx',),
         'an unset, null or empty `cisco_ai_defense.enabled_rules` sends no `config`'),
    ]),
    ('fg05_policy_explain_default_new_run', [
        (('reference/sandboxes/cli.mdx',),
         'describes a new run of the default agent'),
        (('enterprise/runtime/sandboxes.mdx',),
         'it explains a new run of the default agent'),
    ]),
    ('fg05_approval_always_refused_under_floor', [
        (('enterprise/runtime/sandbox-reference.mdx',),
         'With `allow_unblock: false`, the person can approve'),
        (('reference/sandboxes/cli.mdx',),
         '`approve --always` is refused, even when `user_approvals` is unset'),
    ]),
    ('fg05_upstream_telemetry_profile_floor', [
        (('enterprise/runtime/sandbox-reference.mdx',),
         "host's rendered `gateway.env`"),
        (('enterprise/runtime/sandbox-reference.mdx',),
         "`allow_upstream_telemetry: false` has OpenShell's own telemetry off"),
    ]),
    ('fg06_image_build_reference_names_probe_directory', [
        (('reference/sandboxes/cli.mdx',),
         '`sandbox image build <harness> --force` recheck command'),
        (('reference/sandboxes/cli.mdx', 'troubleshooting/sandboxes/macos.mdx'),
         '`~/Library/Caches/defenseclaw/hookfire`'),
    ]),
    ('fg02_duplicate_custom_providers_merge', [
        (('appendix/migrate-v9.mdx',),
         '`migration-v9.json` notes each merged provider'),
        (('appendix/migrate-v9.mdx',),
         "lists are unioned and the later entry's values win"),
    ]),
    ('macos_protected_folder_skip_is_partial', [
        (('enterprise/install/reference/macos.mdx',),
         'protected folders were not scanned'),
        (('enterprise/install/reference/macos.mdx', 'reference/scanning/ai-discovery.mdx'),
         '`detector_errors.macos_privacy`'),
    ]),
    ('fg04a_windows_plugin_refusal_is_structured', [
        (('enterprise/install/reference/windows.mdx',),
         'ASSET-POLICY reason_code=admin-deny'),
    ]),
    ('lfwin_guardian_first_reconcile_wait', [
        (('troubleshooting/enterprise/install.mdx',),
         'no longer running during its first reconcile'),
        (('troubleshooting/enterprise/install.mdx',),
         "Setup waits up to 10 minutes for the guardian's first reconcile"),
    ]),
    ('fg12_uninstall_incomplete_code', [
        (('troubleshooting/enterprise/index.mdx',),
         '| `uninstall_incomplete` |'),
        (('troubleshooting/enterprise/index.mdx',),
         'started the services again'),
    ]),
    ('fg12_linux_package_removal_keeps_files', [
        (('enterprise/install/reference/linux.mdx',),
         'apt or dnf fails and keeps the package files'),
    ]),
    ('fg12_doctor_prints_pinned_driver_digest', [
        (('enterprise/runtime/sandbox-reference.mdx',),
         'install command with the SHA-256 digest this DefenseClaw build pins'),
    ]),
    ('fg11_machine_policy_summary_missing', [
        (('troubleshooting/enterprise/index.mdx',),
         '| `machine_policy_summary_missing` | Windows |'),
    ]),
    ('fg11_stopped_service_verify_is_not_ready', [
        (('troubleshooting/enterprise/index.mdx',),
         '`verify` also reports it'),
    ]),
    ('fg11_rule_pack_preflight_grant', [
        (('troubleshooting/enterprise/index.mdx',),
         "service's derived SID"),
        (('troubleshooting/enterprise/index.mdx',),
         "Setup's config preflight"),
    ]),
    ('fg11_secret_remove_requires_readable_config', [
        (('enterprise/configure/reference.mdx',),
         'refuses when it cannot read the installed config'),
    ]),
    ('fg11_setup_upgrade_file_held', [
        (('troubleshooting/enterprise/install.mdx',),
         'Setup upgrade says another program holds a file open'),
    ]),
    ('fg08_predate_troubleshooting_excludes_self_update', [
        (('enterprise/runtime/tetragon-reference.mdx',),
         'old controls policy enforcing'),
        (('enterprise/runtime/tetragon-reference.mdx',),
         'enforce turned on or Tetragon restarted'),
    ]),
    ('fg08_limit_keeps_old_controls', [
        (('enterprise/runtime/tetragon-reference.mdx',),
         'old controls policy enforcing'),
    ]),
    ('fg08_lifecycle_retains_old_policy', [
        (('enterprise/runtime/tetragon-reference.mdx',),
         'removed when the last one exits'),
    ]),
    ('gap_0038_write_proof_names_child_program_limit_without_recipes', [
        (('reference/commands/guardrail-setup.mdx',),
         '### Protected-file write proof'),
        (('reference/commands/guardrail-setup.mdx',),
         'use a sandbox or file permissions'),
    ]),
    ('gap_0296_manifest_is_in_pinned_digest', [
        (('how-to/policies/validate-a-rule-pack.mdx',),
         'pinned digest also covers the'),
    ]),
    ('gap_0346_allow_rule_marks_example_values', [
        (('reference/scanning/admission.mdx',),
         'Replace the skill name and path with your reviewed asset'),
    ]),
    ('gap_0297_managed_windows_tool_names_are_exact', [
        (('reference/scanning/admission.mdx',),
         'Codex has no `Read` or `Skill` tool name'),
        (('reference/scanning/admission.mdx',),
         'Write these exact names, including capitals'),
    ]),
    ('gap_0300_mcp_scan_verdict_survives_runtime_toggle', [
        (('reference/scanning/admission.mdx',),
         'scan verdict still refuses MCP calls'),
        (('reference/scanning/admission.mdx',),
         'runtime_detection.enabled` is `false`'),
    ]),
    ('gap_0301_claude_skill_call_checks_each_copy_path', [
        (('reference/scanning/admission.mdx',),
         'judges each copy at its own path'),
        (('reference/scanning/admission.mdx',),
         'a matching deny on any copy blocks the call'),
    ]),
    ('gap_0314_equal_custom_policy_can_fold_to_preset', [
        (('appendix/migrate-v9.mdx',),
         '`policy list` can show the preset as active'),
        (('appendix/migrate-v9.mdx',),
         "does not retain an activated custom policy's name"),
    ]),
    ('gap_0309_failed_group_lookup_can_match_verified_identity', [
        (('reference/policy/guardrail-profiles.mdx',),
         'A verified UID, SID or agent'),
    ]),
    ('gap_0312_unreadable_scanner_policy_stops_migration', [
        (('appendix/migrate-v9.mdx',),
         'If the file cannot be read, migration stops'),
    ]),
    ('gap_0299_legacy_install_requires_vacant_data_home', [
        (('appendix/migrate-v9.mdx',),
         'Move the kept data home out of the install location'),
        (('appendix/migrate-v9.mdx',),
         '0.8.x installer refuses a data home that is still there'),
    ]),
    ('gap_0349_ide_inventory_counts_four_ai_plugins', [
        (('reference/scanning/ai-discovery.mdx',),
         '7 plugin(s) shown; 7 in total, 4 AI'),
    ]),
    ('gap_0350_current_kernel_feed_line_has_text_fallback', [
        (('reference/sandboxes/cli.mdx',),
         'An install or update restarts the feed:'),
        (('reference/sandboxes/cli.mdx',),
         'own hook calls in full until you stop and start it'),
    ]),
    ('group_test_macos_output_matches_documented_forms', [
        (('enterprise/install/reference/macos.mdx',),
         'separate per-user CLI, if present, exits `3`'),
        (('enterprise/identity/sources.mdx',),
         'Its JSON output shows the resolved subject and groups'),
    ]),
    ('1101_windows_event_ids', [
        (('enterprise/operate/reference.mdx',),
         '`/ensure` writes 111 or 112 instead'),
    ]),
    ('1101_admission_managed_alternative', [
        (('reference/scanning/admission.mdx',),
         'A standard account is refused'),
        (('reference/scanning/admission.mdx',),
         'The managed Windows CLI has no `config get`'),
    ]),
    ('cli_keep_state_and_purge_rows', [
        (('reference/commands/cli.mdx',),
         'The deployment record goes either way'),
    ]),
    ('gap_0360_landlock_is_an_abi_not_a_kernel_version', [
        (('enterprise/install/reference/linux.mdx', 'enterprise/runtime/sandbox-reference.mdx', 'how-to/sandboxes/set-up-on-linux.mdx', 'reference/sandboxes/cli.mdx', 'troubleshooting/sandboxes/linux.mdx'),
         'Landlock ABI 3 or newer'),
    ]),
    ('gap_0453_pin_is_not_applied_to_windows_profiles', [
        (('reference/scanning/admission.mdx',),
         'This per-copy check is for Linux and macOS'),
    ]),
    ('gap_0377_0659_max_tokens_limits_named', [
        (('reference/connectors/zeptoclaw.mdx',),
         '`max_completion_tokens`'),
    ]),
    ('gap_0586_group_row_precision', [
        (('reference/policy/guardrail-profiles.mdx',),
         'names that contain `@` are skipped'),
        (('reference/policy/guardrail-profiles.mdx',),
         'A numeric group id matches only while no name answers for that group'),
    ]),
    ('gap_0046_standalone_uninstall_removes_lock', [
        (('enterprise/install/reference/windows.mdx',),
         'The Secure Client profile keeps the lock unless `PURGE=1`'),
        (('enterprise/install/reference/windows.mdx',),
         'A standalone Setup uninstall removes the administrator-only'),
    ]),
    ('gap_0060_0061_macos_directory_steps', [
        (('enterprise/configure/reference.mdx',),
         'For Hermes, create its config file'),
        (('enterprise/configure/reference.mdx', 'enterprise/install/macos.mdx', 'enterprise/install/reference/macos.mdx'),
         'sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos reconcile'),
    ]),
    # Facts whose old wording was reworded or moved into the reference pages.
    ("docker_group_is_root_equivalent", [
        (("enterprise/runtime/sandboxes.mdx",),
         "**Docker is root-equivalent.** On Linux a member of the `docker` group can do anything root can."),
        (("enterprise/install/reference/linux.mdx",),
         "Membership in `docker` is root-equivalent: a member can read and change what root"
         " can, including `/etc/defenseclaw/config.yaml`, the protected credentials"),
        (("enterprise/runtime/sandbox-reference.mdx",),
         "Put only the accounts that run sandboxes in `docker`"),
    ]),
    ("managed_config_refuses_inline_credentials", [
        (("enterprise/runtime/sandbox-reference.mdx",),
         "A managed config refuses inline values for `llm.api_key`, `inspect_llm.api_key`, `guardrail.llm.api_key`"),
    ]),
    ("one_account_shares_a_sandbox_trust_boundary", [
        (("enterprise/runtime/sandbox-reference.mdx",),
         "A registration vouches for the account, not for a VM."),
    ]),
    ("host_run_is_refused_for_non_exempt_accounts", [
        (("enterprise/runtime/sandbox-reference.mdx",),
         "For a non-exempt account, a host run is refused even when it claims to be nested in a sandbox, "
         "unless sandboxes are unavailable to the account"),
        (("enterprise/runtime/sandboxes.mdx",),
         "`exempt_users` ([enrollment](/docs/enterprise/configure/enrollment)) are not refused for a required agent"),
    ]),
    ("managed_uninstall_keeps_sandboxes_until_purge", [
        (("enterprise/runtime/sandbox-reference.mdx",),
         "Without `--purge`, uninstall stops running sandboxes through the sandbox daemon"),
        (("enterprise/runtime/sandbox-reference.mdx",),
         "Every sandbox stays with its records, disks and any copy-mode work not pulled yet."),
    ]),
    ("per_user_uninstall_stops_on_a_running_sandbox", [
        (("get-started/uninstall.mdx",),
         "A running sandbox stops the uninstall before any change"),
        (("reference/commands/cli.mdx",),
         "if DefenseClaw cannot read the sandbox list"),
    ]),
    ("rollback_carries_the_sandbox_setup", [
        (("get-started/upgrade.mdx",),
         "Between releases from 1.0.1 on, rollback also carries your sandbox setup"),
        (("get-started/upgrade.mdx",),
         "A release before 1.0.1 cannot take over that setup."),
    ]),
    ("block_message_has_a_length_limit", [
        (("enterprise/configure/configuration.mdx",),
         "`block_message` may contain at most 4096 characters."),
    ]),
    ("windows_packagers_need_a_version_9_config", [
        (("enterprise/mdm/intune/windows-reference.mdx",),
         "The packager requires a `config_version: 9` config"),
    ]),
    ("kiro_cli_prompt_blocks_do_not_stop_the_model", [
        (("connectors/kiro.mdx",),
         "On `kiro-cli --v3`, a blocked prompt still reaches the model with DefenseClaw's reason attached"),
    ]),
    ("windows_wsl2_and_per_user_docker_are_out_of_scope", [
        (("get-started/windows.mdx",),
         "Windows Home, per-user Docker Desktop, WSL2 engines and Windows containers are not supported"),
    ]),
]


def test_runtracked_comment_names_the_linux_containment():
    # w25-misc (0b503331ab) runs a Linux scanner tree as PID 1 of a private PID
    # and user namespace, which closes the custodian SIGKILL escape the comment
    # used to name; the comment names the namespace and the refusal instead.
    source = (ROOT / "internal/processutil/command.go").read_text(encoding="utf-8")
    match = re.search(r"// RunTracked runs.*?\nfunc RunTracked\(", source, re.DOTALL)
    assert match is not None
    comment = " ".join(line.removeprefix("//").strip() for line in match.group().splitlines())
    assert "PID 1 of a new PID and user namespace" in comment
    assert "RunTracked returns ErrNotContained" in comment


@pytest.mark.parametrize("fact", [f[0] for f in FACTS])
def test_docs_keep_the_fact(fact: str) -> None:
    checks = dict(FACTS)[fact]
    for pages, phrase in checks:
        assert any(phrase in _flat(page) for page in pages), (fact, pages, phrase)


def test_sandbox_docs_name_the_openshell_release_setup_installs() -> None:
    version_go = (ROOT / "internal/openshell/version.go").read_text(encoding="utf-8")
    match = re.search(r'InstallerVersion = "(\d+\.\d+\.\d+)"', version_go)
    assert match, "internal/openshell/version.go no longer defines InstallerVersion"
    pinned = match.group(1)
    assert f"Setup installs OpenShell {pinned}" in _flat("features/sandboxes.mdx")
    for page in (
        "features/sandboxes.mdx",
        "enterprise/runtime/sandboxes.mdx",
        "enterprise/runtime/sandbox-reference.mdx",
        "reference/sandboxes/cli.mdx",
    ):
        text = _flat(page)
        for pattern in (
            r"[Ii]nstalls? OpenShell (\d+\.\d+\.\d+)",
            r"upgrades? (?:OpenShell |it )?(?:to )?(\d+\.\d+\.\d+) in place",
            r"\((\d+\.\d+\.\d+) available\)",
        ):
            for found in re.finditer(pattern, text):
                assert found.group(1) == pinned, (page, found.group(0))
