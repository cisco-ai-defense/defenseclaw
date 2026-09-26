// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func claudeOSAdminTestOpts(t *testing.T, agentVersion string) SetupOpts {
	t.Helper()
	root := t.TempDir()
	return SetupOpts{
		ManagedEnterprise: true,
		HookFailMode:      "closed",
		HookExecutable:    filepath.Join(root, "bin", "defenseclaw-hook.exe"),
		DataDir:           filepath.Join(root, "defenseclaw"),
		AgentVersion:      agentVersion,
	}
}

// claudeOSAdminSettings embeds the exported DefenseClaw matrix for exportOpts
// into an administrator's existing policy.
func claudeOSAdminSettings(t *testing.T, exportOpts SetupOpts, extra map[string]interface{}) string {
	t.Helper()
	document, err := ClaudeCodeManagedHookPolicyDocument(exportOpts)
	if err != nil {
		t.Fatalf("export managed hook policy: %v", err)
	}
	var exported map[string]interface{}
	if err := json.Unmarshal(document, &exported); err != nil {
		t.Fatal(err)
	}
	settings := map[string]interface{}{"model": "managed-by-mdm", "hooks": exported["hooks"]}
	for key, value := range extra {
		settings[key] = value
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const claudeOSAdminLabel = `HKLM Settings policy (HKLM\SOFTWARE\Policies\ClaudeCode\Settings)`

func TestClaudeOSAdminPolicyAdmitsTheExportedMatrix(t *testing.T) {
	for _, version := range []string{"2.1.154", "2.1.230"} {
		t.Run(version, func(t *testing.T) {
			opts := claudeOSAdminTestOpts(t, version)
			raw := claudeOSAdminSettings(t, opts, nil)
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, opts); err != nil {
				t.Fatalf("policy carrying the exported matrix was refused: %v", err)
			}
		})
	}
}

func TestClaudeOSAdminPolicyRejectsAMatrixForAnotherContractOrHook(t *testing.T) {
	// A v1 export lacks DirectoryAdded, which the v2 contract requires.
	opts := claudeOSAdminTestOpts(t, "2.1.230")
	stale := opts
	stale.AgentVersion = "2.1.200"
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		claudeOSAdminSettings(t, stale, nil), claudeOSAdminLabel, opts,
	); err == nil {
		t.Fatal("a matrix exported for an older hook contract was accepted")
	}
	other := opts
	other.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	other.DataDir = filepath.Join(t.TempDir(), "defenseclaw")
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		claudeOSAdminSettings(t, other, nil), claudeOSAdminLabel, opts,
	); err == nil {
		t.Fatal("a matrix naming another hook executable was accepted")
	}
}

// TestClaudeOSAdminPolicyMergeDoesNotTrustTheRecordedClientVersion is the
// #899 review regression. The recorded agent_version is written once, at
// discovery, and is often the installer's placeholder (2.1.154 for a user
// with no detected client), so refusing on it failed every lifecycle on an
// AVC-first host even after its users upgraded. It is not proof in the other
// direction either. The client floor for merge is enforced host-wide by the
// lifecycle module's application-control gate, never per target here.
func TestClaudeOSAdminPolicyMergeDoesNotTrustTheRecordedClientVersion(t *testing.T) {
	raw := `{"managedSourcesBehavior":"merge","model":"managed-by-mdm"}`
	for _, version := range []string{
		ClaudeCodeManagedSourcesMergeMinimumVersion,
		"2.1.250",
		"Claude Code 2.1.242",
		"2.1.241",
		"2.1.154",
		"not-a-version",
		"",
	} {
		if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, claudeOSAdminTestOpts(t, version)); err != nil {
			t.Fatalf("merge with recorded Claude %q was refused: %v", version, err)
		}
	}
	// Any other value keeps first-wins precedence.
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		`{"managedSourcesBehavior":"first-wins"}`, claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250"),
	); err == nil {
		t.Fatal("a non-merge managedSourcesBehavior was treated as merge")
	}
}

func TestClaudeOSAdminPolicyRefusalNamesBothFixes(t *testing.T) {
	err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`{"model":"managed-by-mdm"}`, claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250"))
	if err == nil {
		t.Fatalf("shadowing policy = %v, want a refusal", err)
	}
	for _, want := range []string{claudeOSAdminLabel, `"managedSourcesBehavior": "merge"`, ClaudeCodeManagedPolicyExportCommand} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not mention %q", err, want)
		}
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks("{not json", claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250")); err == nil ||
		!strings.Contains(err.Error(), ClaudeCodeManagedPolicyExportCommand) {
		t.Fatalf("malformed policy = %v, want an actionable refusal", err)
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks("   ", claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250")); err != nil {
		t.Fatalf("empty Settings value = %v, want no policy", err)
	}
}

// Hook-defeating gates in the outranking policy win however sources combine.
func TestClaudeOSAdminPolicyHookGatesStillFailClosed(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	for name, raw := range map[string]string{
		"merge disables hooks":   `{"managedSourcesBehavior":"merge","disableAllHooks":true}`,
		"matrix disables hooks":  claudeOSAdminSettings(t, opts, map[string]interface{}{"disableAllHooks": true}),
		"malformed gate":         `{"managedSourcesBehavior":"merge","disableAllHooks":"yes"}`,
		"merge with a helper":    `{"managedSourcesBehavior":"merge","policyHelper":{"path":"C:\\helper.exe"}}`,
		"matrix with a helper":   claudeOSAdminSettings(t, opts, map[string]interface{}{"policyHelper": map[string]interface{}{"path": `C:\helper.exe`}}),
		"merge with bad hooks":   `{"managedSourcesBehavior":"merge","hooks":"none"}`,
		"merge with bad entries": `{"managedSourcesBehavior":"merge","hooks":{"PreToolUse":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, opts); err == nil {
				t.Fatal("hook-defeating outranking policy was accepted")
			}
		})
	}
}

func TestClaudeMergedManagedSourceUnionsBothTiersHooks(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	file := &claudeCodeSettingsSource{name: "file"}
	if file.settings, err = decodeClaudeCodeSettings(document, "file"); err != nil {
		t.Fatal(err)
	}
	osAdmin := &claudeCodeSettingsSource{name: "MDM", settings: map[string]interface{}{
		"managedSourcesBehavior": "merge",
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{
			map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "C:\\audit.exe"}}},
		}},
	}}
	merged, err := claudeCodeMergedManagedSource(osAdmin, file)
	if err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeSourceHasHookContract(merged, opts, false); err != nil || !present {
		t.Fatalf("merged tiers = (present=%v, err=%v), want the DefenseClaw contract", present, err)
	}
	fileEntries := len(file.settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{}))
	if got := len(merged.settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})); got != fileEntries+1 {
		t.Fatalf("merged PreToolUse entries = %d, want %d", got, fileEntries+1)
	}
	withoutFile, err := claudeCodeMergedManagedSource(osAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeSourceHasHookContract(withoutFile, opts, false); err != nil || present {
		t.Fatalf("merge without the DefenseClaw tier = (present=%v, err=%v), want repairable absence", present, err)
	}
}

func TestClaudeCodeManagedHookPolicyDocumentMatchesTheInstalledRendering(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.230")
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderClaudeCodeManagedHookPolicy(opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(document) != string(rendered) {
		t.Fatal("exported document differs from the policy the guardian installs")
	}
	if !strings.Contains(string(document), `"DirectoryAdded"`) {
		t.Fatal("v2 export is missing the v2-only DirectoryAdded hook")
	}
	unmanaged := opts
	unmanaged.ManagedEnterprise = false
	if _, err := ClaudeCodeManagedHookPolicyDocument(unmanaged); err == nil {
		t.Fatal("export rendered a policy outside managed enterprise setup")
	}
}
