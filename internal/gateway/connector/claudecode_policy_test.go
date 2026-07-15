// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatedClaudePolicyFixture(t *testing.T) (*ClaudeCodeConnector, SetupOpts, string, string) {
	t.Helper()
	root := t.TempDir()
	settingsPath := filepath.Join(root, "profile", ".claude", "settings.json")
	managedRoot := filepath.Join(root, "managed", "ClaudeCode")
	workspace := filepath.Join(root, "workspace")
	for _, path := range []string{filepath.Dir(settingsPath), managedRoot, workspace} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previousSettings := ClaudeCodeSettingsPathOverride
	previousManaged := ClaudeCodeManagedSettingsRootOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	ClaudeCodeManagedSettingsRootOverride = managedRoot
	t.Cleanup(func() {
		ClaudeCodeSettingsPathOverride = previousSettings
		ClaudeCodeManagedSettingsRootOverride = previousManaged
	})

	conn := NewClaudeCodeConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "defenseclaw"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "test-token",
		WorkspaceDir: workspace,
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Claude setup: %v", err)
	}
	return conn, opts, settingsPath, managedRoot
}

func writeClaudePolicyJSON(t *testing.T, path string, value interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClaudeEffectivePolicyUsesWorkspacePrecedence(t *testing.T) {
	conn, opts, _, _ := isolatedClaudePolicyFixture(t)
	project := filepath.Join(opts.WorkspaceDir, ".claude", "settings.json")
	local := filepath.Join(opts.WorkspaceDir, ".claude", "settings.local.json")
	writeClaudePolicyJSON(t, project, map[string]interface{}{"disableAllHooks": true})

	if present, err := OwnedHooksPresent(conn, opts); present || err == nil ||
		!strings.Contains(err.Error(), "project settings") || !strings.Contains(err.Error(), project) {
		t.Fatalf("project disable result = (present=%v, err=%v), want exact project source", present, err)
	}

	writeClaudePolicyJSON(t, local, map[string]interface{}{"disableAllHooks": false})
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("local false should override project true: present=%v err=%v", present, err)
	}
}

func TestClaudeEffectivePolicyGatesCLISettings(t *testing.T) {
	conn, opts, _, _ := isolatedClaudePolicyFixture(t)
	opts.ClaudeSettingsOverride = `{"disableAllHooks":true}`
	if present, err := OwnedHooksPresent(conn, opts); present || err == nil ||
		!strings.Contains(err.Error(), "CLI --settings") || !strings.Contains(err.Error(), "disableAllHooks=true") {
		t.Fatalf("inline CLI override result = (present=%v, err=%v)", present, err)
	}

	cliPath := filepath.Join(opts.WorkspaceDir, "claude-session.json")
	writeClaudePolicyJSON(t, cliPath, map[string]interface{}{"disableAllHooks": false})
	opts.ClaudeSettingsOverride = "claude-session.json"
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("relative CLI settings path should be resolved from workspace: present=%v err=%v", present, err)
	}
}

func TestClaudeEffectivePolicyRejectsManagedUserHookGates(t *testing.T) {
	for name, policy := range map[string]map[string]interface{}{
		"allow-managed-only": {"allowManagedHooksOnly": true},
		"strict-bool":        {"strictPluginOnlyCustomization": true},
		"strict-hooks":       {"strictPluginOnlyCustomization": []interface{}{"skills", "hooks"}},
		"disable-all":        {"disableAllHooks": true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, opts, _, _ := isolatedClaudePolicyFixture(t)
			writeClaudePolicyJSON(t, claudeCodeRemoteSettingsPath(), policy)
			present, err := OwnedHooksPresent(conn, opts)
			if present || err == nil || !strings.Contains(err.Error(), "remote/server-managed settings") {
				t.Fatalf("managed gate result = (present=%v, err=%v), want remote source", present, err)
			}
		})
	}
}

func TestClaudeManagedContractUsesWinningManagedSource(t *testing.T) {
	_, userOpts, _, managedRoot := isolatedClaudePolicyFixture(t)
	opts := userOpts
	opts.ManagedEnterprise = true
	opts.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	body, err := NewClaudeCodeConnector().ManagedHookPolicy(opts)
	if err != nil {
		t.Fatalf("render managed policy: %v", err)
	}
	policyPath := filepath.Join(managedRoot, "managed-settings.d", "90-defenseclaw.json")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
		t.Fatalf("file managed contract = (present=%v, err=%v)", present, err)
	}

	writeClaudePolicyJSON(t, claudeCodeRemoteSettingsPath(), map[string]interface{}{"model": "remote-wins"})
	if present, err := claudeCodeEffectiveHookContract(opts); present || err == nil ||
		!strings.Contains(err.Error(), "remote/server-managed settings") || !strings.Contains(err.Error(), "no hooks table") {
		t.Fatalf("remote replacement result = (present=%v, err=%v)", present, err)
	}

	writeClaudePolicyJSON(t, claudeCodeRemoteSettingsPath(), map[string]interface{}{})
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
		t.Fatalf("empty remote should fall through to file contract: present=%v err=%v", present, err)
	}
	if _, err := NewClaudeCodeConnector().ManagedHookPolicy(opts); err != nil {
		t.Fatalf("empty remote should not block file managed destination: %v", err)
	}
}

func TestClaudeEnterpriseScriptContractUsesUserSettings(t *testing.T) {
	conn, opts, _, _ := isolatedClaudePolicyFixture(t)
	opts.ManagedEnterprise = true
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("enterprise script contract = (present=%v, err=%v), want user-settings hook", present, err)
	}
}

func TestClaudeManagedContractMissingFileTierIsRepairable(t *testing.T) {
	_, opts, _, managedRoot := isolatedClaudePolicyFixture(t)
	opts.ManagedEnterprise = true
	opts.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || present {
		t.Fatalf("missing managed file tier = (present=%v, err=%v), want repairable absence", present, err)
	}

	// A lower HKCU policy can be superseded by restoring the file drop-in as
	// well. Model that priority directly without writing the developer's real
	// registry during the test.
	previousLoader := claudeCodeOSManagedSettingsLoader
	claudeCodeOSManagedSettingsLoader = func() (claudeCodeOSManagedSources, error) {
		return claudeCodeOSManagedSources{userFallback: &claudeCodeSettingsSource{
			name:     "HKCU managed settings fallback",
			path:     `HKCU\SOFTWARE\Policies\ClaudeCode\Settings`,
			settings: map[string]interface{}{"disableAllHooks": true},
		}}, nil
	}
	previousSettings := ClaudeCodeSettingsPathOverride
	previousManaged := ClaudeCodeManagedSettingsRootOverride
	ClaudeCodeSettingsPathOverride = ""
	ClaudeCodeManagedSettingsRootOverride = ""
	t.Cleanup(func() {
		claudeCodeOSManagedSettingsLoader = previousLoader
		ClaudeCodeSettingsPathOverride = previousSettings
		ClaudeCodeManagedSettingsRootOverride = previousManaged
	})
	// Preserve fixture file isolation while allowing the injected OS loader.
	// readClaudeCodeManagedFileSettings would otherwise use the real Program
	// Files tree, so point ProgramFiles at the empty fixture parent.
	t.Setenv("ProgramFiles", filepath.Dir(managedRoot))
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || present {
		t.Fatalf("disabling HKCU fallback without managed hook = (present=%v, err=%v), want repairable absence", present, err)
	}
}

func TestClaudeManagedHookPolicyVerificationRequiresCanonicalDocument(t *testing.T) {
	_, opts, _, _ := isolatedClaudePolicyFixture(t)
	opts.ManagedEnterprise = true
	opts.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	conn := NewClaudeCodeConnector()
	body, err := conn.ManagedHookPolicy(opts)
	if err != nil {
		t.Fatalf("render managed policy: %v", err)
	}
	if err := conn.VerifyManagedHookPolicy(body, opts); err != nil {
		t.Fatalf("canonical managed policy rejected: %v", err)
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	minified, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.VerifyManagedHookPolicy(minified, opts); err != nil {
		t.Fatalf("semantically canonical policy with different formatting rejected: %v", err)
	}
	policy["disableAllHooks"] = false
	withExtraSetting, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.VerifyManagedHookPolicy(append(withExtraSetting, '\n'), opts); err == nil ||
		!strings.Contains(err.Error(), "canonical DefenseClaw policy") {
		t.Fatalf("extra top-level setting verification error = %v", err)
	}

	delete(policy, "disableAllHooks")
	hooks := policy["hooks"].(map[string]interface{})
	hooks["UserMaintenance"] = []interface{}{map[string]interface{}{
		"hooks": []interface{}{map[string]interface{}{
			"type":    "command",
			"command": "operator-maintenance.exe",
			"timeout": 5,
		}},
	}}
	withUnrelatedHook, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.VerifyManagedHookPolicy(append(withUnrelatedHook, '\n'), opts); err == nil ||
		!strings.Contains(err.Error(), "canonical DefenseClaw policy") {
		t.Fatalf("unrelated managed hook verification error = %v", err)
	}
}

func TestClaudePolicyHelperIsExplicitlyUninspectable(t *testing.T) {
	conn, opts, _, managedRoot := isolatedClaudePolicyFixture(t)
	writeClaudePolicyJSON(t, claudeCodeRemoteSettingsPath(), map[string]interface{}{"allowManagedHooksOnly": false})
	base := filepath.Join(managedRoot, "managed-settings.json")
	writeClaudePolicyJSON(t, base, map[string]interface{}{
		"policyHelper": map[string]interface{}{"path": filepath.Join(managedRoot, "policy-helper.exe")},
	})
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("active remote source should supersede lower file helper: present=%v err=%v", present, err)
	}

	writeClaudePolicyJSON(t, claudeCodeRemoteSettingsPath(), map[string]interface{}{})
	present, err := OwnedHooksPresent(conn, opts)
	if present || err == nil || !strings.Contains(err.Error(), "policyHelper") ||
		!strings.Contains(err.Error(), base) || !strings.Contains(err.Error(), "cannot be passively verified") {
		t.Fatalf("policyHelper result = (present=%v, err=%v)", present, err)
	}
}

func TestClaudePolicyHelperUsesOnlyActiveEndpointTier(t *testing.T) {
	helper := &claudeCodeSettingsSource{
		name:     "file",
		settings: map[string]interface{}{"policyHelper": map[string]interface{}{"path": "helper"}},
	}
	remote := &claudeCodeSettingsSource{name: "remote", settings: map[string]interface{}{"model": "remote"}}
	osAdmin := &claudeCodeSettingsSource{name: "MDM", settings: map[string]interface{}{"model": "managed"}}

	if got := claudeCodePolicyHelperSource(claudeCodeManagedSourceSet{remote: remote, file: helper}); got != nil {
		t.Fatalf("lower file helper selected under remote source: %#v", got)
	}
	if got := claudeCodePolicyHelperSource(claudeCodeManagedSourceSet{osAdmin: osAdmin, file: helper}); got != nil {
		t.Fatalf("lower file helper selected under OS-admin source: %#v", got)
	}
	if got := claudeCodePolicyHelperSource(claudeCodeManagedSourceSet{
		remote: &claudeCodeSettingsSource{name: "empty remote", settings: map[string]interface{}{}},
		file:   helper,
	}); got != helper {
		t.Fatalf("file helper after empty remote = %#v, want file source", got)
	}
}

func TestClaudeManagedSourcePrecedence(t *testing.T) {
	remote := &claudeCodeSettingsSource{name: "remote", settings: map[string]interface{}{"model": "remote"}}
	osAdmin := &claudeCodeSettingsSource{name: "MDM", settings: map[string]interface{}{"disableAllHooks": true}}
	file := &claudeCodeSettingsSource{name: "file", settings: map[string]interface{}{"allowManagedHooksOnly": true}}
	hkcu := &claudeCodeSettingsSource{name: "HKCU", settings: map[string]interface{}{"strictPluginOnlyCustomization": true}}
	set := claudeCodeManagedSourceSet{remote: remote, osAdmin: osAdmin, file: file, userFallback: hkcu}
	if got := set.active(); got != remote {
		t.Fatalf("active source = %#v, want remote", got)
	}
	set.remote.settings = map[string]interface{}{}
	if got := set.active(); got != osAdmin {
		t.Fatalf("active source after empty remote = %#v, want MDM", got)
	}
	set.remote = nil
	if got := set.active(); got != osAdmin {
		t.Fatalf("active source without remote = %#v, want MDM", got)
	}
	set.osAdmin = nil
	if got := set.active(); got != file {
		t.Fatalf("active source without MDM = %#v, want file", got)
	}
	set.file = nil
	if got := set.active(); got != hkcu {
		t.Fatalf("active source fallback = %#v, want HKCU", got)
	}
}

func TestClaudeManagedDropinsDeepMerge(t *testing.T) {
	_, _, _, managedRoot := isolatedClaudePolicyFixture(t)
	writeClaudePolicyJSON(t, filepath.Join(managedRoot, "managed-settings.json"), map[string]interface{}{
		"strictPluginOnlyCustomization": []interface{}{"skills"},
		"nested":                        map[string]interface{}{"base": true},
	})
	writeClaudePolicyJSON(t, filepath.Join(managedRoot, "managed-settings.d", "20-hooks.json"), map[string]interface{}{
		"strictPluginOnlyCustomization": []interface{}{"hooks"},
		"nested":                        map[string]interface{}{"dropin": true},
	})
	source, err := readClaudeCodeManagedFileSettings()
	if err != nil {
		t.Fatal(err)
	}
	strict, _ := source.settings["strictPluginOnlyCustomization"].([]interface{})
	if len(strict) != 2 || strict[0] != "skills" || strict[1] != "hooks" {
		t.Fatalf("merged strict customization = %#v", strict)
	}
	nested, _ := source.settings["nested"].(map[string]interface{})
	if nested["base"] != true || nested["dropin"] != true {
		t.Fatalf("deep-merged object = %#v", nested)
	}
}

func TestClaudeManagedSettingsRejectsDoctorOversizePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", int(2<<20)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readStableClaudeCodeSettingsFile(path); !exists || err == nil || !strings.Contains(err.Error(), "exceeds 2097152 bytes") {
		t.Fatalf("oversize managed settings = (exists=%v, err=%v)", exists, err)
	}
}
