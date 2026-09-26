// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// claudeHKLMFixture routes every Claude managed source to test fixtures: the
// OS-admin (HKLM) tier is injected and the file tier lives under a fixture
// Program Files, so the machine's real policy is never read.
func claudeHKLMFixture(t *testing.T, hklm map[string]interface{}) (policyPath string) {
	t.Helper()
	programFiles := t.TempDir()
	previousRoot := claudeCodeWindowsProgramFilesRoot
	previousLoader := claudeCodeOSManagedSettingsLoader
	previousSettings := ClaudeCodeSettingsPathOverride
	previousManaged := ClaudeCodeManagedSettingsRootOverride
	claudeCodeWindowsProgramFilesRoot = func() (string, error) { return programFiles, nil }
	claudeCodeOSManagedSettingsLoader = func() (claudeCodeOSManagedSources, error) {
		if hklm == nil {
			return claudeCodeOSManagedSources{}, nil
		}
		return claudeCodeOSManagedSources{admin: &claudeCodeSettingsSource{
			name:     "MDM/OS managed settings",
			path:     `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`,
			settings: hklm,
		}}, nil
	}
	ClaudeCodeSettingsPathOverride = ""
	ClaudeCodeManagedSettingsRootOverride = ""
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	t.Cleanup(func() {
		claudeCodeWindowsProgramFilesRoot = previousRoot
		claudeCodeOSManagedSettingsLoader = previousLoader
		ClaudeCodeSettingsPathOverride = previousSettings
		ClaudeCodeManagedSettingsRootOverride = previousManaged
	})
	return filepath.Join(programFiles, "ClaudeCode", "managed-settings.d", "90-defenseclaw.json")
}

func writeClaudeManagedFileTier(t *testing.T, path string, opts SetupOpts) {
	t.Helper()
	body, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeHKLMMergeAdmitsAndAuditsTheUnionOnWindows(t *testing.T) {
	policyPath := claudeHKLMFixture(t, map[string]interface{}{
		"managedSourcesBehavior": "merge",
		"model":                  "managed-by-mdm",
	})
	opts := claudeOSAdminTestOpts(t, ClaudeCodeManagedSourcesMergeMinimumVersion)
	if _, err := NewClaudeCodeConnector().ManagedHookPolicy(opts); err != nil {
		t.Fatalf("merge-honoring client was refused the file tier: %v", err)
	}
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || present {
		t.Fatalf("merge before the DefenseClaw tier exists = (present=%v, err=%v), want repairable absence", present, err)
	}
	writeClaudeManagedFileTier(t, policyPath, opts)
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
		t.Fatalf("merged HKLM and DefenseClaw tiers = (present=%v, err=%v), want the contract", present, err)
	}
	// Runtime and identity checks re-render the machine-wide policy without
	// a client version; they must keep proving identity under merge.
	body, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := opts
	identity.AgentVersion = ""
	identity.HookContractID = ResolveHookContract("claudecode", opts.AgentVersion).Contract.ContractID
	if err := NewClaudeCodeConnector().VerifyManagedHookPolicy(body, identity); err != nil {
		t.Fatalf("versionless identity verification under HKLM merge = %v", err)
	}

	// #899 review: a row recorded below the merge floor (for example the
	// installer's 2.1.154 placeholder for a user with no detected client)
	// is enrolled and audited like any other. The recorded version cannot
	// show the running client; the lifecycle module withholds the Claude
	// effective-policy claim until application control is attested at the
	// merge floor.
	for _, recorded := range []string{"2.1.241", "2.1.154"} {
		row := opts
		row.AgentVersion = recorded
		if _, err := NewClaudeCodeConnector().ManagedHookPolicy(row); err != nil {
			t.Fatalf("row recorded at %s under HKLM merge was refused: %v", recorded, err)
		}
		writeClaudeManagedFileTier(t, policyPath, row)
		if present, err := claudeCodeEffectiveHookContract(row); err != nil || !present {
			t.Fatalf("row recorded at %s audit = (present=%v, err=%v), want the merged contract", recorded, present, err)
		}
	}
}

func TestClaudeHKLMMergeStillHonorsTheFileTierGates(t *testing.T) {
	policyPath := claudeHKLMFixture(t, map[string]interface{}{"managedSourcesBehavior": "merge"})
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	writeClaudeManagedFileTier(t, policyPath, opts)
	disabler := filepath.Join(filepath.Dir(policyPath), "95-other.json")
	if err := os.WriteFile(disabler, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeEffectiveHookContract(opts); present || err == nil ||
		!strings.Contains(err.Error(), "disableAllHooks=true") {
		t.Fatalf("merged audit with a disabling file tier = (present=%v, err=%v)", present, err)
	}
}

func TestClaudeHKLMCarryingTheMatrixIsEffectiveOnWindows(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.230")
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	var exported map[string]interface{}
	if err := json.Unmarshal(document, &exported); err != nil {
		t.Fatal(err)
	}
	claudeHKLMFixture(t, map[string]interface{}{"model": "managed-by-mdm", "hooks": exported["hooks"]})
	if _, err := NewClaudeCodeConnector().ManagedHookPolicy(opts); err != nil {
		t.Fatalf("HKLM carrying the exported matrix was refused: %v", err)
	}
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
		t.Fatalf("HKLM carrying the exported matrix = (present=%v, err=%v)", present, err)
	}
}

func TestClaudeHKLMShadowingPolicyRefusesWithTheFixOnWindows(t *testing.T) {
	claudeHKLMFixture(t, map[string]interface{}{"model": "managed-by-mdm"})
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	_, err := NewClaudeCodeConnector().ManagedHookPolicy(opts)
	if err == nil || !strings.Contains(err.Error(), ClaudeCodeManagedPolicyExportCommand) ||
		!strings.Contains(err.Error(), "managedSourcesBehavior") {
		t.Fatalf("shadowing HKLM policy = %v, want an actionable refusal", err)
	}
}
