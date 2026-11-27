//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// gap1731OwnFixturesAsTokenUser makes the test account the default owner of
// what this test creates, and puts the token's previous default owner back
// when the test ends. An elevated administrator's token names
// BUILTIN\Administrators as that default owner, so the fixture folders
// (t.TempDir under the managed root and CLAUDE_CONFIG_DIR) would be owned by
// Administrators while the connector's safefile checks require the token
// user: "refusing foreign-owned directory" (GAP-1872). Only these tests need
// it. Other tests in the package rely on elevated Administrators-owned
// fixtures (GAP-1910, GAP-1911, GAP-1916, GAP-1917), so it is not set in
// TestMain. A standard user's token already names itself and nothing changes.
func gap1731OwnFixturesAsTokenUser(t *testing.T) {
	t.Helper()
	previous, err := testenv.OwnNewObjectsAsTokenUser()
	if err != nil {
		t.Fatalf("own new objects as the token user: %v", err)
	}
	t.Cleanup(func() {
		var token windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
			t.Errorf("open the process token to restore the default owner: %v", err)
			return
		}
		defer token.Close()
		owner := struct{ Owner *windows.SID }{previous}
		if err := windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
			t.Errorf("restore the token default owner: %v", err)
		}
	})
}

// gap1731Fixture renders and installs DefenseClaw's drop-in in an isolated
// file tier, then serves hklm as the HKLM Settings policy. It returns the
// drop-in path: the hook contract depends on the Claude Code version, so a
// case that sets AgentVersion installs the render for that version.
func gap1731Fixture(t *testing.T) (SetupOpts, []byte, func(map[string]interface{}), string) {
	t.Helper()
	gap1731OwnFixturesAsTokenUser(t)
	_, opts, _, managedRoot := isolatedClaudePolicyFixture(t)
	opts.ManagedEnterprise = true
	opts.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	body, err := NewClaudeCodeConnector().ManagedHookPolicy(opts)
	if err != nil {
		t.Fatalf("render managed policy without HKLM: %v", err)
	}
	policyPath := filepath.Join(managedRoot, "managed-settings.d", "90-defenseclaw.json")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var hklm map[string]interface{}
	previousLoader := claudeCodeOSManagedSettingsLoader
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
	previousSettings := ClaudeCodeSettingsPathOverride
	previousManaged := ClaudeCodeManagedSettingsRootOverride
	previousProgramFiles := claudeCodeWindowsProgramFilesRoot
	ClaudeCodeSettingsPathOverride = ""
	ClaudeCodeManagedSettingsRootOverride = ""
	// The file tier resolves through the trusted Program Files root, not
	// the environment; point it at the fixture's managed root.
	claudeCodeWindowsProgramFilesRoot = func() (string, error) { return filepath.Dir(managedRoot), nil }
	t.Cleanup(func() {
		claudeCodeOSManagedSettingsLoader = previousLoader
		ClaudeCodeSettingsPathOverride = previousSettings
		ClaudeCodeManagedSettingsRootOverride = previousManaged
		claudeCodeWindowsProgramFilesRoot = previousProgramFiles
	})
	t.Setenv("ProgramFiles", filepath.Dir(managedRoot))
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	return opts, body, func(value map[string]interface{}) { hklm = value }, policyPath
}

// TestGAP1731HKLMMergeAdmitsManagedHooks: an HKLM Claude Code policy that sets
// managedSourcesBehavior: merge (or carries only source-control keys, or
// carries DefenseClaw's matrix) no longer refuses managed enrolment, and the
// guardian audit checks the merged file tier. Fails on a64bfdb931: every
// non-empty HKLM policy refused enrolment.
func TestGAP1731HKLMMergeAdmitsManagedHooks(t *testing.T) {
	opts, body, setHKLM, policyPath := gap1731Fixture(t)
	deny := map[string]interface{}{"deny": []interface{}{"Bash(curl:*)"}}

	for _, tc := range []struct {
		name    string
		hklm    map[string]interface{}
		version string
	}{
		{"merge with a policy key, merge-capable client", map[string]interface{}{"managedSourcesBehavior": "merge", "permissions": deny}, "2.1.250 (Claude Code)"},
		{"merge, versionless re-render", map[string]interface{}{"managedSourcesBehavior": "merge", "permissions": deny}, ""},
		{"only source-control keys, client below the merge floor", map[string]interface{}{"managedSourcesBehavior": "merge", "wslInheritsWindowsSettings": false}, "2.1.200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setHKLM(tc.hklm)
			opts := opts
			opts.AgentVersion = tc.version
			rendered, err := NewClaudeCodeConnector().ManagedHookPolicy(opts)
			if err != nil {
				t.Fatalf("ManagedHookPolicy under HKLM %v: %v", tc.hklm, err)
			}
			// Setup installs the drop-in it rendered for this client version
			// (2.1.250 resolves claudecode-hooks-v2, which adds DirectoryAdded),
			// and the audit checks the contract of that same version.
			if err := os.WriteFile(policyPath, rendered, 0o600); err != nil {
				t.Fatal(err)
			}
			if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
				t.Fatalf("effective contract under HKLM %v = (present=%v, err=%v), want present", tc.hklm, present, err)
			}
		})
	}

	t.Run("HKLM carries the DefenseClaw matrix", func(t *testing.T) {
		var carried map[string]interface{}
		if err := json.Unmarshal(body, &carried); err != nil {
			t.Fatal(err)
		}
		carried["permissions"] = deny
		setHKLM(carried)
		if _, err := NewClaudeCodeConnector().ManagedHookPolicy(opts); err != nil {
			t.Fatalf("ManagedHookPolicy under HKLM carrying the matrix: %v", err)
		}
	})
}

// TestGAP1731HKLMShadowingNamesTheFix: an HKLM policy that hides the drop-in
// still refuses, naming merge (and its client floor) as the fix; merge with
// disableAllHooks or on an older client still refuses.
func TestGAP1731HKLMShadowingNamesTheFix(t *testing.T) {
	opts, _, setHKLM, _ := gap1731Fixture(t)
	deny := map[string]interface{}{"deny": []interface{}{"Bash(curl:*)"}}
	for _, tc := range []struct {
		name    string
		hklm    map[string]interface{}
		version string
		want    string
	}{
		{"policy without merge", map[string]interface{}{"permissions": deny}, "2.1.250", `add "managedSourcesBehavior": "merge"`},
		{"merge on an older client", map[string]interface{}{"managedSourcesBehavior": "merge", "permissions": deny}, "2.1.200", "ignores managedSourcesBehavior: merge"},
		{"merge with disableAllHooks", map[string]interface{}{"managedSourcesBehavior": "merge", "disableAllHooks": true}, "2.1.250", "disableAllHooks=true"},
		{"merge with policyHelper", map[string]interface{}{"managedSourcesBehavior": "merge", "policyHelper": map[string]interface{}{"path": `C:\helper.exe`}}, "2.1.250", "policyHelper"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setHKLM(tc.hklm)
			opts := opts
			opts.AgentVersion = tc.version
			if _, err := NewClaudeCodeConnector().ManagedHookPolicy(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ManagedHookPolicy under HKLM %v = %v, want an error containing %q", tc.hklm, err, tc.want)
			}
			if present, err := claudeCodeEffectiveHookContract(opts); present || err == nil {
				t.Fatalf("effective contract under shadowing HKLM %v = (present=%v, err=%v), want an error", tc.hklm, present, err)
			}
		})
	}
}
