// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
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

func claudeCodeOSAdminRemedy(opts SetupOpts) string {
	return fmt.Sprintf(
		`either set "managedSourcesBehavior": "merge" in that policy (Claude Code %s or newer composes it with the DefenseClaw managed-settings.d policy), or add the "hooks" and "%s" settings printed by %s to it`,
		ClaudeCodeManagedSourcesMergeMinimumVersion,
		claudeCodeManagedHooksOnlyKey,
		claudeCodeManagedPolicyExportCommandFor(opts),
	)
}

// claudeCodeOSAdminAdmitsManagedHooks decides whether DefenseClaw's managed
// hooks are effective under an active OS-admin (HKLM) policy that outranks
// the file-based tier DefenseClaw owns. They are when that policy itself
// carries the DefenseClaw hook entries exactly as rendered for opts
// (first-wins then selects it; see claudeCodeOSAdminCarriesManagedHooks), or
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
	// Claude runs the policy's DefenseClaw handlers under either admission:
	// first-wins loads only that policy, and merge unions its hooks with the
	// drop-in. One on an event outside the target's contract is what an
	// export for another Claude Code version carries, and the guardian's
	// contract audit reports such a registration as missing hooks, so the
	// target would never audit healthy. Name it here instead.
	stray, err := claudeCodeOSAdminStrayManagedHookEvent(source, opts)
	if err != nil {
		return err
	}
	if stray != "" {
		return fmt.Errorf(
			"Claude Code %s registers the DefenseClaw %s hook, which is outside the hook contract this target uses; replace the DefenseClaw hooks in that policy with the ones printed by %s",
			source.label(),
			stray,
			claudeCodeManagedPolicyExportCommandFor(opts),
		)
	}
	carries, err := claudeCodeOSAdminCarriesManagedHooks(source, opts)
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
		claudeCodeOSAdminRemedy(opts),
	)
}

// claudeCodeOSAdminKeepsManagedHooksOnly keeps the DefenseClaw
// managed-hooks-only lock effective under an admitted OS-admin policy. The
// lock is rendered into the DefenseClaw managed-settings.d policy, which the
// outranking policy can override or replace. An explicit
// allowManagedHooksOnly=false there conflicts with the lock however the
// sources combine. A policy that carries the DefenseClaw hooks is the one a
// first-wins client loads on its own (every client without merge, and a
// client older than ClaudeCodeManagedSourcesMergeMinimumVersion with it), so
// it must set allowManagedHooksOnly=true itself. A merge policy that leaves
// the key unset keeps the drop-in lock. The administrator opt-out
// (ClaudeCodeAllowUnmanagedHooks) waives both checks.
func claudeCodeOSAdminKeepsManagedHooksOnly(source *claudeCodeSettingsSource, opts SetupOpts, carriesHooks bool) error {
	if opts.ClaudeCodeAllowUnmanagedHooks {
		return nil
	}
	const optOut = "or set claude_code.allow_unmanaged_hooks: true in the DefenseClaw config"
	// validateClaudeCodeManagedHookControls already refused a non-boolean
	// value, so an error here is an explicit false.
	locked, err := claudeCodeManagedPolicyLockState(source.settings)
	if err != nil {
		return fmt.Errorf(
			"Claude Code %s sets %s=false, which conflicts with the DefenseClaw managed-hooks-only lock; remove the setting %s",
			source.label(),
			claudeCodeManagedHooksOnlyKey,
			optOut,
		)
	}
	if carriesHooks && !locked {
		return fmt.Errorf(
			`Claude Code %s carries the DefenseClaw hooks and outranks the DefenseClaw managed-settings.d policy, so the managed-hooks-only lock in that policy does not apply; add "%s": true (printed by %s) to it, %s`,
			source.label(),
			claudeCodeManagedHooksOnlyKey,
			claudeCodeManagedPolicyExportCommandFor(opts),
			optOut,
		)
	}
	return nil
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
		return fmt.Errorf("%w; the policy outranks the DefenseClaw managed-settings.d policy, so %s", err, claudeCodeOSAdminRemedy(opts))
	}
	source := &claudeCodeSettingsSource{name: label, settings: settings}
	if raw, exists := source.settings["policyHelper"]; exists && raw != nil {
		return fmt.Errorf(
			"Claude Code policyHelper from %s supersedes file-based managed hooks; add the DefenseClaw hook matrix printed by %s to the helper output",
			source.label(),
			claudeCodeManagedPolicyExportCommandFor(opts),
		)
	}
	return claudeCodeOSAdminAdmitsManagedHooks(source, opts)
}

// claudeCodeManagedPolicyExportCommandFor names the export command that
// prints the hook contract opts resolves to. Without --agent-version the
// export renders the default (oldest) Claude contract, which a target on a
// newer contract refuses, so a refusal must name the version to export.
func claudeCodeManagedPolicyExportCommandFor(opts SetupOpts) string {
	contract, err := claudeCodeHookContractForSetup(opts)
	if err != nil {
		return ClaudeCodeManagedPolicyExportCommand
	}
	for _, candidate := range []string{opts.AgentVersion, contract.MinAgentVersion} {
		version := NormalizeAgentVersion("claudecode", candidate)
		if version != "" && ResolveHookContract("claudecode", version).Contract.ContractID == contract.ContractID {
			return ClaudeCodeManagedPolicyExportCommand + " --agent-version " + version
		}
	}
	return ClaudeCodeManagedPolicyExportCommand
}

func claudeCodeOSAdminHooks(source *claudeCodeSettingsSource) (map[string]interface{}, error) {
	rawHooks, exists := source.settings["hooks"]
	if !exists {
		return nil, nil
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Claude Code hooks from %s have unsupported type %T", source.label(), rawHooks)
	}
	return hooks, nil
}

// claudeCodeOSAdminCarriesManagedHooks reports whether an OS-admin policy
// carries every DefenseClaw hook entry exactly as rendered for opts. A
// first-wins client then loads this copy instead of the DefenseClaw drop-in,
// which verify compares exactly, so the copy is held to the same rule: the
// same matcher, timeout, async flag and argv. A shorter timeout, for
// example, lets Claude stop the hook before it can deny. Only the handler
// command compares by path identity, so a path typed in another case still
// matches. Other administrator entries and handlers may sit beside these.
func claudeCodeOSAdminCarriesManagedHooks(source *claudeCodeSettingsSource, opts SetupOpts) (bool, error) {
	hooks, err := claudeCodeOSAdminHooks(source)
	if err != nil || hooks == nil {
		return false, err
	}
	body, err := renderClaudeCodeManagedHookPolicy(opts)
	if err != nil {
		return false, err
	}
	var rendered struct {
		Hooks map[string][]interface{} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &rendered); err != nil {
		return false, fmt.Errorf("parse rendered Claude Code managed hook policy: %w", err)
	}
	command, _ := claudeCodeManagedHookInvocation(opts, filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))
	for event, wanted := range rendered.Hooks {
		entries, _ := hooks[event].([]interface{})
		present := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			if text, ok := claudeCodeCanonicalOSAdminHookEntry(entry, command, opts); ok {
				present[text] = struct{}{}
			}
		}
		for _, entry := range wanted {
			text, ok := claudeCodeCanonicalJSON(entry)
			if !ok {
				return false, fmt.Errorf("canonicalize the rendered Claude Code %s hook", event)
			}
			if _, found := present[text]; !found {
				return false, nil
			}
		}
	}
	return true, nil
}

// claudeCodeCanonicalOSAdminHookEntry is the canonical JSON of one policy
// hook entry with each DefenseClaw handler's command replaced by the
// rendered spelling.
func claudeCodeCanonicalOSAdminHookEntry(raw interface{}, command string, opts SetupOpts) (string, bool) {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	normalized := cloneClaudeCodeSettingsMap(entry)
	if handlers, ok := entry["hooks"].([]interface{}); ok {
		rewritten := make([]interface{}, len(handlers))
		for i, rawHandler := range handlers {
			rewritten[i] = rawHandler
			if handler, ok := rawHandler.(map[string]interface{}); ok && claudeCodeHandlerTargetsCurrentRuntime(handler, opts) {
				handler = cloneClaudeCodeSettingsMap(handler)
				handler["command"] = command
				rewritten[i] = handler
			}
		}
		normalized["hooks"] = rewritten
	}
	return claudeCodeCanonicalJSON(normalized)
}

// claudeCodeCanonicalJSON is key-sorted JSON with every number in float64
// form, so 30 and 30.0 compare equal whichever decoder produced them.
func claudeCodeCanonicalJSON(value interface{}) (string, bool) {
	first, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	var decoded interface{}
	if err := json.Unmarshal(first, &decoded); err != nil {
		return "", false
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return "", false
	}
	return string(canonical), true
}

// claudeCodeOSAdminStrayManagedHookEvent returns the first event, in sorted
// order, outside the contract opts resolves to on which the policy
// registers the DefenseClaw hook, or "" when there is none.
func claudeCodeOSAdminStrayManagedHookEvent(source *claudeCodeSettingsSource, opts SetupOpts) (string, error) {
	hooks, err := claudeCodeOSAdminHooks(source)
	if err != nil || len(hooks) == 0 {
		return "", err
	}
	groups, err := claudeCodeHookGroupsForSetup(opts)
	if err != nil {
		return "", err
	}
	contract := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		contract[group.eventType] = struct{}{}
	}
	events := make([]string, 0, len(hooks))
	for event := range hooks {
		if _, expected := contract[event]; !expected {
			events = append(events, event)
		}
	}
	sort.Strings(events)
	for _, event := range events {
		if entries, ok := hooks[event].([]interface{}); ok && claudeCodeEventTargetsCurrentRuntime(entries, opts) {
			return event, nil
		}
	}
	return "", nil
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
