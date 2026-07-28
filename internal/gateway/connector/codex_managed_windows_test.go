// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestCodexManagedHooksPreserveUnrelatedConfigWithoutPrivateTrustState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelatedState := map[string]interface{}{
		"trusted_hash": "sha256:operator-owned",
		"enabled":      false,
		"note":         "preserve",
	}
	seed := map[string]interface{}{
		"operator_policy": map[string]interface{}{"mode": "strict"},
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{map[string]interface{}{
				"matcher": "^Shell$",
				"hooks": []interface{}{map[string]interface{}{
					"type":    "command",
					"command": "operator-policy.exe",
					"timeout": int64(7),
				}},
			}},
			"state": map[string]interface{}{"operator-key": unrelatedState},
		},
	}
	seedRaw, err := toml.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, seedRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })
	previousInspector := codexPolicyInspector
	managedOnly := true
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{AllowManagedHooksOnly: &managedOnly, Source: "test managed-only policy"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "defenseclaw"), APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup under allow_managed_hooks_only: %v", err)
	}
	configured := readCASTOML(t, managedPath)
	operatorPolicy, _ := configured["operator_policy"].(map[string]interface{})
	if operatorPolicy["mode"] != "strict" {
		t.Fatalf("unrelated managed setting changed: %#v", configured)
	}
	hooks := configured["hooks"].(map[string]interface{})
	state := hooks["state"].(map[string]interface{})
	if len(state) != 1 || !codexValueMatches(state["operator-key"], unrelatedState) {
		t.Fatalf("Setup changed or synthesized managed trust state: %#v", state)
	}
	groups := hooks["PreToolUse"].([]interface{})
	if len(groups) != 2 {
		t.Fatalf("PreToolUse groups = %d, want operator + DefenseClaw: %#v", len(groups), groups)
	}
	operatorHandler := groups[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
	if operatorHandler["command"] != "operator-policy.exe" {
		t.Fatalf("operator managed hook changed: %#v", operatorHandler)
	}
	if err := verifyManagedCodexHookMatrix(hooks, managedPath, filepath.Join(opts.DataDir, "hooks")); err != nil {
		t.Fatalf("managed hook matrix: %v", err)
	}
	if got := conn.HookCapabilities(opts).ConfigPath; got != managedPath {
		t.Fatalf("HookCapabilities ConfigPath = %q, want %q", got, managedPath)
	}

	// Force drift so teardown must perform its surgical CAS merge instead of
	// restoring the pristine file wholesale.
	configured["operator_after_setup"] = map[string]interface{}{"kept": true}
	drifted, err := toml.Marshal(configured)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(managedPath, drifted, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored := readCASTOML(t, managedPath)
	if restored["operator_after_setup"].(map[string]interface{})["kept"] != true {
		t.Fatalf("teardown erased concurrent managed setting: %#v", restored)
	}
	restoredHooks := restored["hooks"].(map[string]interface{})
	if got := codexOwnedHookCount(t, restoredHooks, filepath.Join(opts.DataDir, "hooks")); got != 0 {
		t.Fatalf("teardown left %d DefenseClaw managed hooks: %#v", got, restoredHooks)
	}
	restoredState := restoredHooks["state"].(map[string]interface{})
	if len(restoredState) != 1 || !codexValueMatches(restoredState["operator-key"], unrelatedState) {
		t.Fatalf("teardown changed unrelated managed trust state: %#v", restoredState)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func TestCodexManagedHookPatchRollsBackWhenUserConfigRejectsSetup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[features]\nhooks = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := []byte("[operator_policy]\nmode = \"strict\"\n")
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "defenseclaw"), APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err == nil {
		t.Fatal("Setup succeeded despite features.hooks=false")
	}
	after, err := os.ReadFile(managedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(seed) {
		t.Fatalf("failed Setup did not restore managed_config.toml exactly\nbefore:\n%s\nafter:\n%s", seed, after)
	}
	if _, err := os.Stat(managedFileBackupPath(opts.DataDir, conn.Name(), codexManagedConfigLogicalName)); !os.IsNotExist(err) {
		t.Fatalf("managed rollback backup survived failed Setup: %v", err)
	}
}

func TestCodexTeardownExactRestoreDoesNotResurrectLegacyUserHooks(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	dataDir := filepath.Join(dir, "defenseclaw")
	hooksDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	operatorState := map[string]interface{}{
		"trusted_hash": "sha256:operator-owned",
		"enabled":      false,
		"note":         "preserve",
	}
	hooks := codexLegacyHooksForExactRestoreTest(t, configPath, hooksDir, operatorState)
	seed := map[string]interface{}{
		"model": "gpt-5",
		"hooks": hooks,
	}
	seedRaw, err := toml.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, seedRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	configured := readCASTOML(t, configPath)
	if err := verifyNoOwnedCodexHooks(configured, hooksDir); err != nil {
		t.Fatalf("Setup left legacy user hooks active: %v", err)
	}

	// Do not drift config.toml: teardown must take the exact-backup branch and
	// still filter the legacy DefenseClaw matrix out of the pristine preimage.
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored := readCASTOML(t, configPath)
	if err := verifyNoOwnedCodexHooks(restored, hooksDir); err != nil {
		t.Fatalf("exact restore resurrected legacy user hooks: %v", err)
	}
	if restored["model"] != "gpt-5" {
		t.Fatalf("teardown changed unrelated user config: %#v", restored)
	}
	assertCodexOperatorHookAndStatePreserved(t, restored, operatorState)
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func TestCodexTeardownExactRestoreDoesNotResurrectManagedHooks(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	dataDir := filepath.Join(dir, "defenseclaw")
	hooksDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

	operatorState := map[string]interface{}{
		"trusted_hash": "sha256:managed-operator",
		"enabled":      true,
		"note":         "preserve",
	}
	hooks := codexLegacyHooksForExactRestoreTest(t, managedPath, hooksDir, operatorState)
	seed := map[string]interface{}{
		"operator_policy": map[string]interface{}{"mode": "strict"},
		"hooks":           hooks,
	}
	seedRaw, err := toml.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, seedRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored := readCASTOML(t, managedPath)
	if err := verifyNoOwnedCodexHooks(restored, hooksDir); err != nil {
		t.Fatalf("exact restore resurrected managed hooks: %v", err)
	}
	operatorPolicy, _ := restored["operator_policy"].(map[string]interface{})
	if operatorPolicy["mode"] != "strict" {
		t.Fatalf("teardown changed unrelated managed config: %#v", restored)
	}
	assertCodexOperatorHookAndStatePreserved(t, restored, operatorState)
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func codexLegacyHooksForExactRestoreTest(
	t *testing.T,
	configPath string,
	hooksDir string,
	operatorState map[string]interface{},
) map[string]interface{} {
	t.Helper()
	hooks := map[string]interface{}{
		"PreToolUse": []interface{}{map[string]interface{}{
			"matcher": "^Shell$",
			"hooks": []interface{}{map[string]interface{}{
				"type":    "command",
				"command": "operator-policy.exe",
				"timeout": int64(7),
			}},
		}},
		"state": map[string]interface{}{"operator-key": operatorState},
	}
	if err := mergeOwnedCodexHooks(
		hooks,
		configPath,
		filepath.Join(hooksDir, "codex-hook.sh"),
		hooksDir,
		true,
	); err != nil {
		t.Fatalf("seed legacy Codex hooks: %v", err)
	}
	return hooks
}

func assertCodexOperatorHookAndStatePreserved(
	t *testing.T,
	document map[string]interface{},
	operatorState map[string]interface{},
) {
	t.Helper()
	hooks, ok := document["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("operator hooks table was removed: %#v", document)
	}
	groups, _ := hooks["PreToolUse"].([]interface{})
	if len(groups) != 1 {
		t.Fatalf("operator PreToolUse groups = %d, want 1: %#v", len(groups), hooks)
	}
	group, _ := groups[0].(map[string]interface{})
	handlers, _ := group["hooks"].([]interface{})
	if len(handlers) != 1 {
		t.Fatalf("operator handlers = %d, want 1: %#v", len(handlers), group)
	}
	handler, _ := handlers[0].(map[string]interface{})
	if handler["command"] != "operator-policy.exe" || group["matcher"] != "^Shell$" {
		t.Fatalf("operator hook changed: %#v", group)
	}
	state, _ := hooks["state"].(map[string]interface{})
	if len(state) != 1 || !codexValueMatches(state["operator-key"], operatorState) {
		t.Fatalf("operator trust state changed: %#v", state)
	}
}
