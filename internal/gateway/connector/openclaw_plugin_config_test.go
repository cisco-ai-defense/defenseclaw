// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestGAP0690OpenClawPluginConfigMigration(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "openclaw.json")
	entry := map[string]interface{}{
		"hooks": map[string]interface{}{"allowConversationAccess": true},
		"config": map[string]interface{}{
			"level":        float64(3),
			"operatorNote": "note",
			"mode":         "action",
			"agent":        map[string]interface{}{"id": "alice", "extra": true},
			"awsHttp1Shim": "invalid",
		},
	}
	writeOpenClawJSON(t, configPath, map[string]interface{}{
		"plugins": map[string]interface{}{"entries": map[string]interface{}{"defenseclaw": entry}},
	})
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	extDir := filepath.Join(home, "extensions", "defenseclaw")
	if err := patchOpenClawConfig(configPath, extDir, false, false, false); err != nil {
		t.Fatal(err)
	}
	got := readOpenClawEntries(t, configPath)["defenseclaw"].(map[string]interface{})
	want := map[string]interface{}{
		"enabled": true,
		"hooks":   map[string]interface{}{"allowConversationAccess": true},
		"config": map[string]interface{}{
			"mode":  "action",
			"agent": map[string]interface{}{"id": "alice"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entry after migration = %v, want %v", got, want)
	}
	backups, err := filepath.Glob(configPath + ".defenseclaw-plugin-config.*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backup count = %d, err = %v", len(backups), err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup does not preserve the prior config: %v", err)
	}
	info, err := os.Stat(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, want 0600", info.Mode().Perm())
	}
	// Windows has no POSIX mode bits; owner-only means a private DACL there.
	if err := safefile.ValidatePrivateFile(backups[0]); err != nil {
		t.Fatalf("backup is not private to the owner: %v", err)
	}
	first, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := patchOpenClawConfig(configPath, extDir, false, false, false); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("second setup changed the migrated config: %v", err)
	}
}

func TestGAP0690OpenClawPluginConfigAcceptedTwin(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "openclaw.json")
	writeOpenClawJSON(t, configPath, map[string]interface{}{
		"plugins": map[string]interface{}{"entries": map[string]interface{}{"defenseclaw": map[string]interface{}{
			"config": map[string]interface{}{"mode": "observe", "agent": map[string]interface{}{"id": "alice"}},
		}}},
	})
	if err := patchOpenClawConfig(configPath, filepath.Join(home, "extensions", "defenseclaw"), false, false, false); err != nil {
		t.Fatal(err)
	}
	entry := readOpenClawEntries(t, configPath)["defenseclaw"].(map[string]interface{})
	if entry["enabled"] != true || !reflect.DeepEqual(entry["config"], map[string]interface{}{
		"mode": "observe", "agent": map[string]interface{}{"id": "alice"},
	}) {
		t.Fatalf("accepted plugin config changed: %v", entry)
	}
	backups, err := filepath.Glob(configPath + ".defenseclaw-plugin-config.*.bak")
	if err != nil || len(backups) != 0 {
		t.Fatalf("accepted config created a backup: %v, %v", backups, err)
	}
	// The result must also be valid JSON for OpenClaw to read.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
}
