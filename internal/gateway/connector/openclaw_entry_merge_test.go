// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeOpenClawJSON(t *testing.T, path string, cfg map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readOpenClawEntries(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("openclaw.json is not valid JSON: %v", err)
	}
	plugins, _ := cfg["plugins"].(map[string]interface{})
	entries, _ := plugins["entries"].(map[string]interface{})
	return entries
}

func operatorOpenClawEntryKeys() map[string]interface{} {
	return map[string]interface{}{
		"hooks": map[string]interface{}{
			"allowConversationAccess": true,
			"timeouts":                map[string]interface{}{"before_tool_call": float64(60000)},
		},
		"config": map[string]interface{}{"awsHttp1Shim": "off"},
	}
}

// GAP-0596: setup sets enabled=true and keeps the keys an operator wrote
// under plugins.entries.defenseclaw (it used to replace the entry).
func TestGAP0596OpenClawSetupKeepsOperatorEntryKeys(t *testing.T) {
	ocHome := t.TempDir()
	configPath := filepath.Join(ocHome, "openclaw.json")
	entry := operatorOpenClawEntryKeys()
	entry["enabled"] = false
	writeOpenClawJSON(t, configPath, map[string]interface{}{
		"plugins": map[string]interface{}{
			"entries": map[string]interface{}{
				"defenseclaw":   entry,
				"somebody-else": map[string]interface{}{"enabled": true},
			},
		},
	})

	extDir := filepath.Join(ocHome, "extensions", "defenseclaw")
	for i := 0; i < 2; i++ { // the gateway runs setup on every start
		if err := patchOpenClawConfig(configPath, extDir, false, false, false, openClawPluginKeys{}); err != nil {
			t.Fatalf("patchOpenClawConfig run %d: %v", i+1, err)
		}
	}

	entries := readOpenClawEntries(t, configPath)
	want := operatorOpenClawEntryKeys()
	want["enabled"] = true
	if got := entries["defenseclaw"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("plugins.entries.defenseclaw = %v, want %v", got, want)
	}
	if got := entries["somebody-else"]; !reflect.DeepEqual(got, map[string]interface{}{"enabled": true}) {
		t.Fatalf("unrelated entry changed: %v", got)
	}
}

// Benign twin: with no entry, setup writes exactly {"enabled": true}.
func TestGAP0596OpenClawSetupWritesOnlyEnabledForANewEntry(t *testing.T) {
	ocHome := t.TempDir()
	configPath := filepath.Join(ocHome, "openclaw.json")
	writeOpenClawJSON(t, configPath, map[string]interface{}{})

	if err := patchOpenClawConfig(configPath, filepath.Join(ocHome, "extensions", "defenseclaw"), false, false, false, openClawPluginKeys{}); err != nil {
		t.Fatal(err)
	}
	entries := readOpenClawEntries(t, configPath)
	if got := entries["defenseclaw"]; !reflect.DeepEqual(got, map[string]interface{}{"enabled": true}) {
		t.Fatalf("plugins.entries.defenseclaw = %v, want {enabled:true}", got)
	}
}

// GAP-0596: teardown takes back only what setup wrote. Operator keys under
// the entry stay, the plugin is no longer registered, and VerifyClean does
// not count the operator's keys as DefenseClaw residue.
func TestGAP0596OpenClawTeardownKeepsOperatorEntryKeys(t *testing.T) {
	dataDir := t.TempDir()
	ocHome := filepath.Join(dataDir, "openclaw-home")
	if err := os.MkdirAll(ocHome, 0o755); err != nil {
		t.Fatal(err)
	}
	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()

	configPath := filepath.Join(ocHome, "openclaw.json")
	entry := operatorOpenClawEntryKeys()
	entry["enabled"] = true
	writeOpenClawJSON(t, configPath, map[string]interface{}{
		"plugins": map[string]interface{}{
			"allow":   []interface{}{"defenseclaw"},
			"entries": map[string]interface{}{"defenseclaw": entry},
		},
	})

	if err := uninstallOpenClawExtension(openClawPathsIn(ocHome), false, openClawSetupGrant{}); err != nil {
		t.Fatalf("uninstallOpenClawExtension: %v", err)
	}
	entries := readOpenClawEntries(t, configPath)
	if got := entries["defenseclaw"]; !reflect.DeepEqual(got, operatorOpenClawEntryKeys()) {
		t.Fatalf("plugins.entries.defenseclaw after teardown = %v, want the operator keys only", got)
	}
	if openClawConfigRegistersDefenseClaw(configPath) {
		t.Fatal("teardown left the DefenseClaw plugin registered")
	}
	if err := NewOpenClawConnector().VerifyClean(SetupOpts{DataDir: dataDir}); err != nil {
		t.Fatalf("VerifyClean counted operator keys as residue: %v", err)
	}

	// An entry that still holds DefenseClaw's own key is residue.
	entries["defenseclaw"] = map[string]interface{}{"enabled": true}
	writeOpenClawJSON(t, configPath, map[string]interface{}{"plugins": map[string]interface{}{"entries": entries}})
	if err := NewOpenClawConnector().VerifyClean(SetupOpts{DataDir: dataDir}); err == nil {
		t.Fatal("VerifyClean accepted an entry that DefenseClaw still enables")
	}
}
