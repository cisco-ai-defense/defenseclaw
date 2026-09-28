// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func managedClaudeLockFixture(t *testing.T) (*ClaudeCodeConnector, SetupOpts, string) {
	t.Helper()
	root := t.TempDir()
	managedRoot := filepath.Join(root, "managed", "ClaudeCode")
	if err := os.MkdirAll(managedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previousSettings, previousManaged := ClaudeCodeSettingsPathOverride, ClaudeCodeManagedSettingsRootOverride
	ClaudeCodeSettingsPathOverride = filepath.Join(root, "profile", ".claude", "settings.json")
	ClaudeCodeManagedSettingsRootOverride = managedRoot
	t.Cleanup(func() {
		ClaudeCodeSettingsPathOverride, ClaudeCodeManagedSettingsRootOverride = previousSettings, previousManaged
	})
	opts := SetupOpts{
		ManagedEnterprise: true,
		DataDir: filepath.Join(root, "defenseclaw"),
		HookExecutable: filepath.Join(root, "defenseclaw-hook.exe"),
		WorkspaceDir: filepath.Join(root, "workspace"),
	}
	return NewClaudeCodeConnector(), opts, managedRoot
}

func decodeManagedClaudePolicy(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var policy map[string]interface{}
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatalf("parse managed policy: %v", err)
	}
	return policy
}

// The managed drop-in must carry the vendor lock that keeps user, project,
// local and plugin PreToolUse hooks (which can return updatedInput) from
// running beside the DefenseClaw managed hook.
func TestClaudeManagedPolicyLocksToManagedHooksByDefault(t *testing.T) {
	conn, opts, _ := managedClaudeLockFixture(t)
	body, err := conn.ManagedHookPolicy(opts)
	if err != nil {
		t.Fatalf("render managed policy: %v", err)
	}
	policy := decodeManagedClaudePolicy(t, body)
	if policy["allowManagedHooksOnly"] != true {
		t.Fatalf("default managed policy allowManagedHooksOnly = %#v, want true", policy["allowManagedHooksOnly"])
	}
	if _, ok := policy["hooks"].(map[string]interface{}); !ok {
		t.Fatalf("default managed policy lost its hook matrix: %s", body)
	}
	if len(policy) != 2 {
		t.Fatalf("default managed policy keys = %v, want only hooks and allowManagedHooksOnly", policy)
	}
	locked, err := ClaudeCodeManagedHookPolicyEnforcesManagedOnly(body)
	if err != nil || !locked {
		t.Fatalf("lock state = (%v, %v), want locked", locked, err)
	}
	if err := conn.VerifyManagedHookPolicy(body, opts); err != nil {
		t.Fatalf("locked canonical policy rejected: %v", err)
	}
}

func TestClaudeManagedPolicyLockKeepsManagedContractEffective(t *testing.T) {
	conn, opts, managedRoot := managedClaudeLockFixture(t)
	body, err := conn.ManagedHookPolicy(opts)
	if err != nil {
		t.Fatalf("render managed policy: %v", err)
	}
	writeClaudePolicyJSON(t, filepath.Join(managedRoot, "managed-settings.d", "90-defenseclaw.json"), decodeManagedClaudePolicy(t, body))
	if present, err := claudeCodeEffectiveHookContract(opts); err != nil || !present {
		t.Fatalf("locked managed contract = (present=%v, err=%v), want present", present, err)
	}
}

func TestClaudeManagedPolicyAdminOptOutOmitsLock(t *testing.T) {
	conn, opts, _ := managedClaudeLockFixture(t)
	opts.ClaudeCodeAllowUnmanagedHooks = true
	body, err := conn.ManagedHookPolicy(opts)
	if err != nil {
		t.Fatalf("render opted-out policy: %v", err)
	}
	policy := decodeManagedClaudePolicy(t, body)
	if _, exists := policy["allowManagedHooksOnly"]; exists {
		t.Fatalf("opted-out policy still sets allowManagedHooksOnly: %s", body)
	}
	locked, err := ClaudeCodeManagedHookPolicyEnforcesManagedOnly(body)
	if err != nil || locked {
		t.Fatalf("opted-out lock state = (%v, %v), want unlocked", locked, err)
	}
}

// Read-only verifiers have no administrator configuration, so they accept
// exactly the two DefenseClaw-rendered forms regardless of opts; enterprise
// verify pins the configured form by comparing bytes.
func TestClaudeManagedPolicyVerifyAcceptsOnlyCanonicalLockForms(t *testing.T) {
	conn, opts, _ := managedClaudeLockFixture(t)
	locked, err := conn.ManagedHookPolicy(opts)
	if err != nil {
		t.Fatal(err)
	}
	optOut := opts
	optOut.ClaudeCodeAllowUnmanagedHooks = true
	unlocked, err := conn.ManagedHookPolicy(optOut)
	if err != nil {
		t.Fatal(err)
	}
	for name, verifyOpts := range map[string]SetupOpts{"default": opts, "opt-out": optOut} {
		for form, body := range map[string][]byte{"locked": locked, "unlocked": unlocked} {
			if err := conn.VerifyManagedHookPolicy(body, verifyOpts); err != nil {
				t.Fatalf("%s verifier rejected %s canonical form: %v", name, form, err)
			}
		}
	}

	for name, value := range map[string]interface{}{
		"false":  false,
		"string": "true",
		"number": 1,
	} {
		t.Run(name, func(t *testing.T) {
			policy := decodeManagedClaudePolicy(t, locked)
			policy["allowManagedHooksOnly"] = value
			body, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			err = conn.VerifyManagedHookPolicy(body, opts)
			if err == nil || !strings.Contains(err.Error(), "allowManagedHooksOnly must be true or absent") {
				t.Fatalf("verify with allowManagedHooksOnly=%#v error = %v", value, err)
			}
			if _, err := ClaudeCodeManagedHookPolicyEnforcesManagedOnly(body); err == nil {
				t.Fatalf("lock state accepted allowManagedHooksOnly=%#v", value)
			}
		})
	}
}
