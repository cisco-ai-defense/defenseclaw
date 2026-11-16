// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsStandaloneHookClosureIsKeptUntilProvenRelease(t *testing.T) {
	layout := managed.StandaloneLayout{HookRuntimeDir: t.TempDir()}
	path := windowsStandaloneHookClosurePath(layout)
	ensure, write, trust, dirTrust := windowsStandaloneHookClosureEnsure, windowsStandaloneHookClosureWrite, windowsManagedPolicyFileTrustCheck, windowsManagedPolicyDirTrustCheck
	windowsStandaloneHookClosureEnsure = func(string) error { return nil }
	windowsStandaloneHookClosureWrite = func(path string, body []byte, _ bool) error { return os.WriteFile(path, body, 0o600) }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsStandaloneHookClosureEnsure, windowsStandaloneHookClosureWrite, windowsManagedPolicyFileTrustCheck, windowsManagedPolicyDirTrustCheck = ensure, write, trust, dirTrust
	})
	windowsManagedPolicyDirTrustCheck = func(string) error { return errors.New("untrusted closure directory") }
	if held, err := windowsStandaloneHookClosureHeldClosed(layout); err == nil || !held {
		t.Fatalf("untrusted directory hid closure: held=%t err=%v", held, err)
	}
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	if held, err := readWindowsStandaloneHookClosure(path); err != nil || held {
		t.Fatalf("before undo: held=%t err=%v", held, err)
	}
	if err := CloseWindowsStandaloneHooksForUnprovenUndo(layout); err != nil {
		t.Fatal(err)
	}
	if held, err := readWindowsStandaloneHookClosure(path); err != nil || !held {
		t.Fatalf("after closure: held=%t err=%v", held, err)
	}
	// Repeating a failed undo must not remove or weaken the existing hold.
	if err := CloseWindowsStandaloneHooksForUnprovenUndo(layout); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unexpected marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if held, err := readWindowsStandaloneHookClosure(path); err == nil || !held {
		t.Fatalf("damaged closure: held=%t err=%v", held, err)
	}
	if err := ReleaseWindowsStandaloneHookClosure(layout); err == nil {
		t.Fatal("damaged closure was released")
	}
	if err := os.WriteFile(path, windowsStandaloneHookClosureBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseWindowsStandaloneHookClosure(layout); err != nil {
		t.Fatal(err)
	}
	if held, err := readWindowsStandaloneHookClosure(path); err != nil || held {
		t.Fatalf("after proven release: held=%t err=%v", held, err)
	}
	if _, err := os.Lstat(filepath.Join(layout.HookRuntimeDir, windowsStandaloneHookClosureFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closure remains after release: %v", err)
	}
}
