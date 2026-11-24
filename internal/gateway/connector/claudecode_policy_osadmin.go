// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// claudeCodeMergeMinimumVersion is the first Claude Code release that applies
// managedSourcesBehavior: "merge", so a higher-ranked OS-admin policy no
// longer hides the file-based tier (enterprisepolicy keeps the same floor).
const claudeCodeMergeMinimumVersion = "2.1.242"

// claudeCodeSourceControlKeys only steer how Claude Code selects managed
// sources. A source that carries nothing else is skipped and the next managed
// source applies.
var claudeCodeSourceControlKeys = map[string]bool{
	"managedSourcesBehavior":     true,
	"wslInheritsWindowsSettings": true,
}

// claudeCodeSourceHasPolicyKey reports whether Claude Code selects this
// managed source: it carries at least one non-null key other than the
// source-control keys.
func claudeCodeSourceHasPolicyKey(source *claudeCodeSettingsSource) bool {
	if source == nil {
		return false
	}
	for key, value := range source.settings {
		if !claudeCodeSourceControlKeys[key] && value != nil {
			return true
		}
	}
	return false
}

// claudeCodeOSAdminComposition is what an OS-admin (HKLM) policy means for
// DefenseClaw's file-based drop-in on one client.
type claudeCodeOSAdminComposition int

const (
	// claudeCodeOSAdminNone: no OS-admin policy is selected; the file tier
	// (DefenseClaw's drop-in) applies.
	claudeCodeOSAdminNone claudeCodeOSAdminComposition = iota
	// claudeCodeOSAdminCarriesMatrix: the OS-admin policy wins and itself
	// carries DefenseClaw's complete hook matrix.
	claudeCodeOSAdminCarriesMatrix
	// claudeCodeOSAdminMerges: the OS-admin policy sets
	// managedSourcesBehavior: "merge" for a client that honours it, so Claude
	// Code applies the union of the OS-admin and file tiers.
	claudeCodeOSAdminMerges
)

// classifyClaudeCodeOSAdminPolicy decides whether DefenseClaw's file-based
// managed hooks stay effective under an OS-admin policy. Windows only: other
// platforms keep refusing any OS-admin policy that carries a policy key. An
// error means the drop-in is shadowed (or the policy disables hooks) and names
// the fix. A versionless check (an identity re-render) admits merge; the
// version-aware enrolment and audit paths hold the client floor.
func classifyClaudeCodeOSAdminPolicy(source *claudeCodeSettingsSource, opts SetupOpts) (claudeCodeOSAdminComposition, error) {
	if !claudeCodeSourceHasPolicyKey(source) {
		return claudeCodeOSAdminNone, nil
	}
	shadowed := claudeCodeOSAdminShadowedError{message: fmt.Sprintf(
		"Claude Code %s has higher precedence than file-based managed hooks and does not carry DefenseClaw's hook matrix; add \"managedSourcesBehavior\": \"merge\" to it (Claude Code %s or later) or deploy the DefenseClaw hook matrix through that source",
		source.label(), claudeCodeMergeMinimumVersion,
	)}
	if runtime.GOOS != "windows" {
		return claudeCodeOSAdminNone, shadowed
	}
	if raw, exists := source.settings["policyHelper"]; exists && raw != nil {
		return claudeCodeOSAdminNone, fmt.Errorf( //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			"Claude Code policyHelper from %s supersedes file-based managed hooks; add the DefenseClaw hook matrix to the helper output",
			source.label(),
		)
	}
	if err := validateClaudeCodeManagedHookControls(source, true); err != nil {
		return claudeCodeOSAdminNone, err
	}
	carries, err := claudeCodeSourceHasHookContract(source, opts, false)
	if err != nil {
		return claudeCodeOSAdminNone, err
	}
	if carries {
		return claudeCodeOSAdminCarriesMatrix, nil
	}
	behavior, _ := source.settings["managedSourcesBehavior"].(string)
	if behavior != "merge" {
		return claudeCodeOSAdminNone, shadowed
	}
	if version := NormalizeAgentVersion("claudecode", opts.AgentVersion); version != "" &&
		compareVersion(version, claudeCodeMergeMinimumVersion) < 0 {
		return claudeCodeOSAdminNone, fmt.Errorf( //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			"Claude Code %s ignores managedSourcesBehavior: merge from %s (it needs %s or later), so the policy hides DefenseClaw's file-based managed hooks; upgrade Claude Code or deploy the DefenseClaw hook matrix through that source",
			version, source.label(), claudeCodeMergeMinimumVersion,
		)
	}
	return claudeCodeOSAdminMerges, nil
}

// claudeCodeOSAdminShadowedError is the plain shadowing verdict: the OS-admin
// policy neither carries DefenseClaw's matrix nor merges managed sources.
type claudeCodeOSAdminShadowedError struct{ message string }

func (e claudeCodeOSAdminShadowedError) Error() string { return e.message }

// ClaudeCodeOSAdminPolicyAdmitsManagedHooks applies the OS-admin rules to the
// raw Settings value of an already authenticated policy source (the Windows
// enterprise install gate reads HKLM itself after checking the key ACL).
func ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, label string, opts SetupOpts) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	settings, err := decodeClaudeCodeSettings([]byte(raw), label)
	if err != nil {
		return err
	}
	_, err = classifyClaudeCodeOSAdminPolicy(&claudeCodeSettingsSource{name: label, settings: settings}, opts)
	return err
}

// claudeCodeOSAdminDefersToGuardian reports a plain shadowing verdict that a
// caller without the hook executable cannot make: the policy carries its own
// hooks table that names a DefenseClaw hook or has its hook arguments, so it
// may be DefenseClaw's matrix. The enrolment gate and the guardian's Claude Code rows check it
// against the installed hook. A table that names no DefenseClaw hook cannot
// be the matrix and is not deferred: the Setup preflight refuses it before
// anything changes (GAP-1801 (a)).
func claudeCodeOSAdminDefersToGuardian(source *claudeCodeSettingsSource, opts SetupOpts, err error) bool {
	var plain claudeCodeOSAdminShadowedError
	if !errors.As(err, &plain) || strings.TrimSpace(opts.HookExecutable) != "" {
		return false
	}
	hooks, hasHooks := source.settings["hooks"]
	return hasHooks && claudeCodeHooksTableNamesDefenseClaw(hooks)
}

// claudeCodeHooksTableNamesDefenseClaw reports whether a hooks table may hold
// DefenseClaw's hook: a value names DefenseClaw (its hook executable lives
// under a DefenseClaw folder and is named defenseclaw-*), or a handler has
// DefenseClaw's hook arguments. Enrolment matches the handler's command by
// file identity, so a matrix may name the installed hook by an alias (an 8.3
// short path, a hard link) that carries no DefenseClaw text; deferring on the
// arguments keeps the deferral a superset of what enrolment admits
// (claudeCodeHandlerTargetsCurrentRuntime, GAP-2175). A table that cannot be
// encoded is deferred, as before.
func claudeCodeHooksTableNamesDefenseClaw(hooks interface{}) bool {
	data, err := json.Marshal(hooks)
	if err != nil {
		return true
	}
	if strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
		return true
	}
	events, _ := hooks.(map[string]interface{})
	for _, rawEntries := range events {
		entries, _ := rawEntries.([]interface{})
		for _, rawEntry := range entries {
			entry, _ := rawEntry.(map[string]interface{})
			handlers, _ := entry["hooks"].([]interface{})
			for _, rawHandler := range handlers {
				handler, ok := claudeCodeExecView(rawHandler).(map[string]interface{})
				if !ok {
					continue
				}
				args, ok := claudeCodeNativeExecArguments(handler)
				if ok && (codexValueMatches(args, []string{"hook", "--connector", "claudecode"}) ||
					codexValueMatches(args, []string{"hook", "--connector", "claudecode", "--enterprise-managed"})) {
					return true
				}
			}
		}
	}
	return false
}

// claudeCodeOSAdminMergeCaveats names what a merging OS-admin policy leaves
// to chance (GAP-1801 (b), (c)). The policy is admitted, but status warns:
// an explicit allowManagedHooksOnly: false can override the drop-in's lock
// under merge, and without a requiredMinimumVersion of 2.1.242 or later a
// Claude Code 2.1.154 to 2.1.241 that a user runs reads only this policy and
// runs no DefenseClaw hooks.
func claudeCodeOSAdminMergeCaveats(source *claudeCodeSettingsSource) []string {
	if source == nil {
		return nil
	}
	var caveats []string
	if unlock, ok := source.settings["allowManagedHooksOnly"].(bool); ok && !unlock {
		caveats = append(caveats, fmt.Sprintf(
			"Claude Code %s sets allowManagedHooksOnly: false, which under merge can override the DefenseClaw drop-in's allowManagedHooksOnly: true, so user and project hooks may run; remove it from that source or set it to true",
			source.label(),
		))
	}
	floor, _ := source.settings["requiredMinimumVersion"].(string)
	floor = NormalizeAgentVersion("claudecode", floor)
	if floor == "" || compareVersion(floor, claudeCodeMergeMinimumVersion) < 0 {
		caveats = append(caveats, fmt.Sprintf(
			"Claude Code %s does not require %s or later, so a Claude Code 2.1.154 to 2.1.241 that a user runs reads only that source and runs no DefenseClaw hooks; add \"requiredMinimumVersion\": \"%s\" to it",
			source.label(), claudeCodeMergeMinimumVersion, claudeCodeMergeMinimumVersion,
		))
	}
	return caveats
}

// ClaudeCodeOSAdminPolicyMergeCaveats is claudeCodeOSAdminMergeCaveats for the
// installed OS-admin policy, or nil when it does not merge managed sources or
// cannot be read (ClaudeCodeOSAdminPolicyStatus reports those).
func ClaudeCodeOSAdminPolicyMergeCaveats(opts SetupOpts) []string {
	if ClaudeCodeSettingsPathOverride != "" || ClaudeCodeManagedSettingsRootOverride != "" {
		return nil
	}
	sources, err := claudeCodeOSManagedSettingsLoader()
	if err != nil {
		return nil
	}
	composition, err := classifyClaudeCodeOSAdminPolicy(sources.admin, opts)
	if err != nil || composition != claudeCodeOSAdminMerges {
		return nil
	}
	return claudeCodeOSAdminMergeCaveats(sources.admin)
}

// ClaudeCodeOSAdminPolicyPreflight is the Setup preflight's verdict on the raw
// HKLM Settings value before anything is installed: nil when the value is
// empty, carries only source-control keys, merges managed sources, or carries
// a hooks table that names a DefenseClaw hook or has its hook arguments
// (checked at enrolment); otherwise the refusal naming the fix (GAP-1731,
// GAP-1801, GAP-2175).
func ClaudeCodeOSAdminPolicyPreflight(raw, label string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	settings, err := decodeClaudeCodeSettings([]byte(raw), label)
	if err != nil {
		return err
	}
	source := &claudeCodeSettingsSource{name: label, settings: settings}
	opts := SetupOpts{ManagedEnterprise: true}
	if _, err := classifyClaudeCodeOSAdminPolicy(source, opts); err != nil && !claudeCodeOSAdminDefersToGuardian(source, opts, err) {
		return err
	}
	return nil
}

// ClaudeCodeOSAdminPolicyStatus is the read-only status view of the OS-admin
// policy: whether it shadows DefenseClaw's file-based managed hooks, whether
// it merges managed sources, and a one-line detail. It never fails: a read or
// parse error is reported as shadowed with the error as the detail.
func ClaudeCodeOSAdminPolicyStatus(opts SetupOpts) (shadowed, merges bool, detail string) {
	if ClaudeCodeSettingsPathOverride != "" || ClaudeCodeManagedSettingsRootOverride != "" {
		return false, false, ""
	}
	sources, err := claudeCodeOSManagedSettingsLoader()
	if err != nil {
		return true, false, err.Error()
	}
	composition, err := classifyClaudeCodeOSAdminPolicy(sources.admin, opts)
	if claudeCodeOSAdminDefersToGuardian(sources.admin, opts, err) {
		return false, false, fmt.Sprintf("Claude Code %s carries its own hooks table; the guardian's Claude Code rows verify that it holds DefenseClaw's hook matrix", sources.admin.label())
	}
	if err != nil {
		return true, false, err.Error()
	}
	switch composition {
	case claudeCodeOSAdminCarriesMatrix:
		return false, false, fmt.Sprintf("Claude Code %s carries DefenseClaw's hook matrix", sources.admin.label())
	case claudeCodeOSAdminMerges:
		return false, true, fmt.Sprintf("Claude Code %s sets managedSourcesBehavior: merge, so Claude Code %s and later also apply DefenseClaw's file-based managed hooks", sources.admin.label(), claudeCodeMergeMinimumVersion)
	}
	return false, false, ""
}
