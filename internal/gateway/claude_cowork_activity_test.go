// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func readCoworkActivity(t *testing.T, dataDir string) (coworkActivity, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, "cowork", CoworkActivityFile))
	if os.IsNotExist(err) {
		return coworkActivity{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var activity coworkActivity
	if err := json.Unmarshal(data, &activity); err != nil {
		t.Fatalf("%s: %v", data, err)
	}
	return activity, true
}

// GAP-0038: the last Cowork hook call survives a gateway restart.
func TestPersistCoworkActivityKeepsTheLastCoworkEvent(t *testing.T) {
	dataDir := t.TempDir()
	start := time.Date(2026, 11, 4, 5, 57, 51, 0, time.UTC)

	// No setup cowork on this account: no folder, no file.
	persistCoworkActivity(dataDir, "SessionStart", start)
	if _, ok := readCoworkActivity(t, dataDir); ok {
		t.Fatal("wrote outside a cowork folder setup cowork made")
	}
	if err := os.Mkdir(filepath.Join(dataDir, "cowork"), 0o700); err != nil {
		t.Fatal(err)
	}
	persistCoworkActivity(dataDir, "SessionStart", start)
	got, ok := readCoworkActivity(t, dataDir)
	if !ok || got.LastActivityAt == nil || !got.LastActivityAt.Equal(start) || got.LastSessionStartAt == nil || !got.LastSessionStartAt.Equal(start) {
		t.Fatalf("after SessionStart: %+v", got)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(dataDir, "cowork", CoworkActivityFile)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v (%v), want 0600", info.Mode().Perm(), err)
		}
	}
	// Calls within a minute do not rewrite it; a later one does, keeping the
	// SessionStart time.
	persistCoworkActivity(dataDir, "PreToolUse", start.Add(10*time.Second))
	if got, _ := readCoworkActivity(t, dataDir); !got.LastActivityAt.Equal(start) {
		t.Fatalf("rewritten within the interval: %+v", got)
	}
	later := start.Add(2 * time.Minute)
	persistCoworkActivity(dataDir, "PostToolUse", later)
	got, _ = readCoworkActivity(t, dataDir)
	if !got.LastActivityAt.Equal(later) || !got.LastSessionStartAt.Equal(start) {
		t.Fatalf("after a later call: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Join(dataDir, "cowork"))
	if len(entries) != 1 {
		t.Fatalf("cowork folder holds %d entries, want only %s", len(entries), CoworkActivityFile)
	}
}
