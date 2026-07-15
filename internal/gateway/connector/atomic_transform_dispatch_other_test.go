// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicTransformWithStateDirUsesSuppliedDirectoryOnPOSIX(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "stable-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("stop after V1 receipt publication")
	restore := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase, _ atomicTransformPhaseState,
	) error {
		if phase == atomicTransformPhaseIntentPersisted {
			return crash
		}
		return nil
	})
	t.Cleanup(restore)

	err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
		},
	)
	if !errors.Is(err, crash) {
		t.Fatalf("transform error = %v, want injected receipt boundary", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".defenseclaw-cas-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("supplied state directory has no V1 receipt: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".defenseclaw-cas-state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("POSIX stable-state API created target-local recovery directory: %v", err)
	}
}

func TestAtomicTransformWithStateDirClearsSuccessfulReceiptBeforeLifecycleChange(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "stable-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	replace := func(data string) error {
		return atomicTransformFileWithStateDir(
			path, stateDir, 0o600,
			func(_ []byte, _ bool) (atomicTransformResult, error) {
				return atomicTransformResult{Data: []byte(data)}, nil
			},
		)
	}
	assertNoReceipts := func() {
		t.Helper()
		entries, err := os.ReadDir(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".defenseclaw-cas-") {
				t.Fatalf("successful transform retained recovery artifact %q", entry.Name())
			}
		}
	}

	if err := replace(`{"first":true}`); err != nil {
		t.Fatal(err)
	}
	assertNoReceipts()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"restored":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replace(`{"second":true}`); err != nil {
		t.Fatalf("next lifecycle mutation after target restore: %v", err)
	}
	assertNoReceipts()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"second":true}` {
		t.Fatalf("final body = %q, want second replacement", body)
	}
}
