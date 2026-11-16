// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// Direct connector Setup cannot publish administrator-owned machine requirements.
// It must refuse before changing either the user's config or an old managed file.
func TestCodexManagedWindowsDirectSetupRefusesWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	configSeed := []byte("model = \"gpt-5\"\n")
	managedSeed := []byte("[operator_policy]\nmode = \"strict\"\n")
	for path, data := range map[string][]byte{configPath: configSeed, managedPath: managedSeed} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })
	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "defenseclaw"), ManagedEnterprise: true, InstallCodeGuard: true}
	if err := conn.Setup(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "administrator-owned machine requirements installer") {
		t.Fatalf("managed direct Setup error = %v, want machine requirements refusal", err)
	}
	for path, want := range map[string][]byte{configPath: configSeed, managedPath: managedSeed} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("managed direct Setup changed %s", path)
		}
	}
	if _, err := os.Stat(opts.DataDir); !os.IsNotExist(err) {
		t.Fatalf("managed direct Setup created runtime: %v", err)
	}
}

func TestCodexTeardownCleansLegacyManagedHooksWithoutResurrectingThem(t *testing.T) {
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
		SetupOpts{},
		true,
		codexHookGroups,
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

func verifyNoOwnedCodexHooks(document map[string]interface{}, hooksDir string) error {
	rawHooks, exists := document["hooks"]
	if !exists {
		return nil
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return fmt.Errorf("hooks has unsupported type %T", rawHooks)
	}
	for eventType, rawGroups := range hooks {
		if eventType == "state" {
			continue
		}
		locations, err := ownedCodexHookLocations(runtime.GOOS, codexHookEventKeyLabel(eventType), rawGroups, hooksDir)
		if err != nil {
			return fmt.Errorf("hooks.%s: %w", eventType, err)
		}
		if len(locations) > 0 {
			return fmt.Errorf("hooks.%s still contains %d DefenseClaw handlers", eventType, len(locations))
		}
	}
	return nil
}
