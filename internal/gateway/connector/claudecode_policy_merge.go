// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"runtime"
	"strings"
)

// ClaudeCodeManagedSourcesMergeMinimumVersion is the first Claude Code
// release in which "managedSourcesBehavior": "merge" in the highest-ranked
// managed source composes every administrator source, with hook lists
// unioned across them. Older clients ignore the key and keep first-wins
// precedence, so only the highest-ranked source applies. Under a merge
// policy that does not itself carry the DefenseClaw hooks this is therefore
// the effective approved-client floor; the Windows lifecycle module reports
// Claude effective policy unverified until application control is attested
// at this floor.
const ClaudeCodeManagedSourcesMergeMinimumVersion = "2.1.242"

// ClaudeCodeManagedPolicyExportCommand prints the exact DefenseClaw hook
// matrix an administrator can embed in a higher-precedence policy.
const ClaudeCodeManagedPolicyExportCommand = "defenseclaw-gateway enterprise windows export-claude-policy"

// claudeCodeOSAdminPolicyComposition gates the OS-admin composition rules to
// the Windows HKLM tier. Other platforms keep refusing an active OS-admin
// policy until their MDM composition is certified.
var claudeCodeOSAdminPolicyComposition = runtime.GOOS == "windows"

func claudeCodeSourceRequestsManagedMerge(source *claudeCodeSettingsSource) bool {
	if !source.active() {
		return false
	}
	behavior, ok := source.settings["managedSourcesBehavior"].(string)
	return ok && behavior == "merge"
}

func claudeCodeOSAdminRemedy() string {
	return fmt.Sprintf(
		`either set "managedSourcesBehavior": "merge" in that policy (Claude Code %s or newer composes it with the DefenseClaw managed-settings.d policy), or add the DefenseClaw hook matrix printed by %s to its hooks`,
		ClaudeCodeManagedSourcesMergeMinimumVersion,
		ClaudeCodeManagedPolicyExportCommand,
	)
}

// claudeCodeOSAdminAdmitsManagedHooks decides whether DefenseClaw's managed
// hooks are effective under an active OS-admin (HKLM) policy that outranks
// the file-based tier DefenseClaw owns. They are when that policy itself
// carries the complete DefenseClaw contract (first-wins then selects it), or
// when it opts into merging managed sources, which clients honor from
// ClaudeCodeManagedSourcesMergeMinimumVersion. A policy that disables hooks
// defeats both, and anything else fails closed with the two ways to fix it.
func claudeCodeOSAdminAdmitsManagedHooks(source *claudeCodeSettingsSource, opts SetupOpts) error {
	if !source.active() {
		return nil
	}
	if err := validateClaudeCodeManagedHookControls(source, true); err != nil {
		return err
	}
	carries, err := claudeCodeSourceHasHookContract(source, opts, false)
	if err != nil {
		return err
	}
	if carries {
		return nil
	}
	if claudeCodeSourceRequestsManagedMerge(source) {
		// Merge makes the DefenseClaw hooks effective on Claude Code
		// ClaudeCodeManagedSourcesMergeMinimumVersion or newer. The target's
		// recorded agent_version cannot show which client actually runs: it
		// is recorded once, at discovery, and is often the installer's
		// placeholder. So it neither admits nor refuses the target here.
		// Refusing on it failed the whole lifecycle for rows that could never
		// be updated, while a row recorded as new proved nothing. The floor
		// is enforced host-wide instead: Status reports the Claude effective
		// policy unverified until approved-client application control is
		// attested at that version. The guardian audits the union of both
		// tiers, so a hook list that cannot be merged is refused here.
		_, err := claudeCodeMergedManagedSource(source, nil)
		return err
	}
	return fmt.Errorf(
		"Claude Code %s has higher precedence than the DefenseClaw managed-settings.d policy, so Claude would never load the DefenseClaw hooks; %s",
		source.label(),
		claudeCodeOSAdminRemedy(),
	)
}

// ClaudeCodeOSAdminPolicyAdmitsManagedHooks applies the OS-admin composition
// rules to a raw HKLM Settings document. The caller authenticates the
// registry key; this decides only what its content means for opts.
func ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, label string, opts SetupOpts) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	settings, err := decodeClaudeCodeSettings([]byte(raw), label)
	if err != nil {
		return fmt.Errorf("%w; the policy outranks the DefenseClaw managed-settings.d policy, so %s", err, claudeCodeOSAdminRemedy())
	}
	source := &claudeCodeSettingsSource{name: label, settings: settings}
	if raw, exists := source.settings["policyHelper"]; exists && raw != nil {
		return fmt.Errorf(
			"Claude Code policyHelper from %s supersedes file-based managed hooks; add the DefenseClaw hook matrix printed by %s to the helper output",
			source.label(),
			ClaudeCodeManagedPolicyExportCommand,
		)
	}
	return claudeCodeOSAdminAdmitsManagedHooks(source, opts)
}

// claudeCodeMergedManagedSource is what a merge-honoring client loads from
// the OS-admin and file tiers: every scalar gate is checked separately by the
// caller, and the hook lists of both tiers are unioned per event.
func claudeCodeMergedManagedSource(osAdmin, file *claudeCodeSettingsSource) (*claudeCodeSettingsSource, error) {
	merged := map[string]interface{}{}
	for _, source := range []*claudeCodeSettingsSource{osAdmin, file} {
		if !source.active() {
			continue
		}
		rawHooks, exists := source.settings["hooks"]
		if !exists {
			continue
		}
		hooks, ok := rawHooks.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Claude Code hooks from %s have unsupported type %T", source.label(), rawHooks)
		}
		for event, rawEntries := range hooks {
			entries, ok := rawEntries.([]interface{})
			if !ok {
				return nil, fmt.Errorf("Claude Code %s hooks from %s have unsupported type %T", event, source.label(), rawEntries)
			}
			existing, _ := merged[event].([]interface{})
			merged[event] = append(append([]interface{}(nil), existing...), entries...)
		}
	}
	return &claudeCodeSettingsSource{
		name:     fmt.Sprintf("merged %s and file-based managed settings", osAdmin.label()),
		settings: map[string]interface{}{"hooks": merged},
	}, nil
}

// ClaudeCodeManagedHookPolicyDocument renders the DefenseClaw managed hook
// matrix for opts without consulting the destination tiers, so an
// administrator can export it into a higher-precedence policy that would
// otherwise make ManagedHookPolicy refuse.
func ClaudeCodeManagedHookPolicyDocument(opts SetupOpts) ([]byte, error) {
	if !opts.ManagedEnterprise {
		return nil, fmt.Errorf("Claude Code managed hook policy requires managed enterprise setup")
	}
	return renderClaudeCodeManagedHookPolicy(opts)
}
