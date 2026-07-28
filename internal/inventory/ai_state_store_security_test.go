// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAIStateStoreSecureCreateAndRewrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "AI state space")
	path := filepath.Join(dir, "ai_discovery_state.json")
	store := NewAIStateStore(path)

	if err := store.Save(aiStateFile{Signals: map[string]aiStoredSignal{}}); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	if err := store.Save(aiStateFile{Signals: map[string]aiStoredSignal{}}); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"version": 2`) {
		t.Fatalf("unexpected state payload: %s", body)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("state mode = %o, want 600", got)
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".safefile-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staging files left behind: %v", matches)
	}
}

func TestAIStateStoreSaveFailureIsReturned(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("synthetic fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewAIStateStore(filepath.Join(blocker, "state.json"))
	if err := store.Save(aiStateFile{}); err == nil {
		t.Fatal("Save returned nil for an unusable parent path")
	}
}

func TestAIDiscoveryStateSaveFailureIsVisibleInReport(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("synthetic fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &ContinuousDiscoveryService{
		opts:  AIDiscoveryOptions{Mode: "passive"},
		store: NewAIStateStore(filepath.Join(blocker, "state.json")),
	}
	report := service.classifyAndPersist(
		"scan-fixture",
		"manual",
		time.Now(),
		nil,
		scanStats{DetectorErrors: map[string]string{}, DetectorDurations: map[string]int{}},
		aiStateFile{Signals: map[string]aiStoredSignal{}},
		true,
	)
	if report.Summary.Result != "partial" || report.Summary.Errors != 1 {
		t.Fatalf("persistence failure summary = %+v", report.Summary)
	}
	if report.Summary.DetectorErrors["state_store"] == "" {
		t.Fatal("state_store persistence error was not surfaced")
	}
}
