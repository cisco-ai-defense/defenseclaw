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

// persistCoworkActivityWithin runs persistCoworkActivity and fails the test
// when it does not return within a few seconds (it runs in the hook path).
func persistCoworkActivityWithin(t *testing.T, dataDir, event string, now time.Time) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		persistCoworkActivity(dataDir, event, now)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("persistCoworkActivity blocked on the previous record")
	}
}

// plantCoworkActivityRecord puts plant's entry at the record path of a fresh
// cowork folder and returns the data dir and that path.
func plantCoworkActivityRecord(t *testing.T, plant func(t *testing.T, path string)) (string, string) {
	t.Helper()
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, "cowork"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "cowork", CoworkActivityFile)
	plant(t, path)
	return dataDir, path
}

// requireFreshCoworkActivity checks that the call wrote a regular record of
// now alone: nothing of the planted entry was read.
func requireFreshCoworkActivity(t *testing.T, dataDir, path string, now time.Time) {
	t.Helper()
	got, ok := readCoworkActivity(t, dataDir)
	if !ok || got.LastActivityAt == nil || !got.LastActivityAt.Equal(now) || got.LastSessionStartAt != nil {
		t.Fatalf("record after the call = %+v (written %v), want only last_activity_at %s", got, ok, now)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("record is not a regular file after the call: %v %v", info, err)
	}
}

func oldCoworkActivityRecord(t *testing.T) []byte {
	t.Helper()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data, err := json.Marshal(coworkActivity{LastActivityAt: &old, LastSessionStartAt: &old})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// GAP-0038 (review): the hook path reads the previous record only from a
// regular file of at most coworkActivityMaxBytes, without following a link.
// A linked or oversized record reads as none: the call returns at once and
// a fresh record replaces the entry, and a link target is left as it was.
func TestPersistCoworkActivityIgnoresALinkedOrOversizedRecord(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	old := oldCoworkActivityRecord(t)

	t.Run("symlink to a record", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(target, old, 0o600); err != nil {
			t.Fatal(err)
		}
		dataDir, path := plantCoworkActivityRecord(t, func(t *testing.T, path string) {
			if err := os.Symlink(target, path); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("this Windows token cannot create a symbolic link: %v", err)
				}
				t.Fatal(err)
			}
		})
		persistCoworkActivityWithin(t, dataDir, "PreToolUse", now)
		requireFreshCoworkActivity(t, dataDir, path, now)
		if data, err := os.ReadFile(target); err != nil || string(data) != string(old) {
			t.Fatalf("link target changed: %q %v", data, err)
		}
	})

	t.Run("oversized record", func(t *testing.T) {
		dataDir, path := plantCoworkActivityRecord(t, func(t *testing.T, path string) {
			// Valid JSON, one byte over the cap once padded.
			padded := append(append([]byte{}, old...), make([]byte, coworkActivityMaxBytes+1-len(old))...)
			for i := len(old); i < len(padded); i++ {
				padded[i] = ' '
			}
			if err := os.WriteFile(path, padded, 0o600); err != nil {
				t.Fatal(err)
			}
		})
		persistCoworkActivityWithin(t, dataDir, "PreToolUse", now)
		requireFreshCoworkActivity(t, dataDir, path, now)
	})

	t.Run("record at the cap is still read", func(t *testing.T) {
		dataDir, _ := plantCoworkActivityRecord(t, func(t *testing.T, path string) {
			padded := append(append([]byte{}, old...), make([]byte, coworkActivityMaxBytes-len(old))...)
			for i := len(old); i < len(padded); i++ {
				padded[i] = ' '
			}
			if err := os.WriteFile(path, padded, 0o600); err != nil {
				t.Fatal(err)
			}
		})
		persistCoworkActivityWithin(t, dataDir, "PreToolUse", now)
		if got, _ := readCoworkActivity(t, dataDir); got.LastSessionStartAt == nil || !got.LastActivityAt.Equal(now) {
			t.Fatalf("a record of exactly %d bytes was not kept: %+v", coworkActivityMaxBytes, got)
		}
	})
}
