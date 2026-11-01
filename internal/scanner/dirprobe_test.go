// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// guardFolder makes rawOpenDir answer like macOS privacy protection for
// guarded: EINTR after a pause past the retry window, every time.
func guardFolder(t *testing.T, guarded string) *int {
	t.Helper()
	calls := 0
	oldOpen, oldWindow := rawOpenDir, dirProbeRetryWindow
	dirProbeRetryWindow = 20 * time.Millisecond
	rawOpenDir = func(dir string) error {
		if dir != guarded {
			return nil
		}
		calls++
		time.Sleep(30 * time.Millisecond)
		return syscall.EINTR
	}
	t.Cleanup(func() { rawOpenDir, dirProbeRetryWindow = oldOpen, oldWindow })
	return &calls
}

func tccTree(t *testing.T) (root, guarded string) {
	t.Helper()
	root = t.TempDir()
	guarded = filepath.Join(root, "Documents")
	for _, p := range []string{filepath.Join(root, "ok.py"), filepath.Join(guarded, "secret.py")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("print(1)\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, guarded
}

func TestGAP1529AGuardedFolderEndsAStrictWalkWithAnIncompleteScan(t *testing.T) {
	root, guarded := tccTree(t)
	calls := guardFolder(t, guarded)
	for name, walk := range map[string]func(string, bool) ([]string, error){
		"codeguard":  collectCodeFiles,
		"clawshield": csCollectAllFiles,
	} {
		*calls = 0
		_, err := walk(root, true)
		if !errors.Is(err, ErrIncompleteScan) || !errors.Is(err, errFolderPrivacyProtected) || !errors.Is(err, syscall.EINTR) {
			t.Fatalf("%s strict walk: err = %v, want incomplete scan naming privacy protection", name, err)
		}
		if *calls < 1 {
			t.Fatalf("%s: guarded folder not probed", name)
		}
		files, err := walk(root, false)
		if err != nil {
			t.Fatalf("%s best-effort walk: %v", name, err)
		}
		for _, f := range files {
			if filepath.Dir(f) == guarded {
				t.Fatalf("%s best-effort walk read the guarded folder: %v", name, files)
			}
		}
		if len(files) != 1 || filepath.Base(files[0]) != "ok.py" {
			t.Fatalf("%s best-effort walk: files = %v, want ok.py only", name, files)
		}
	}
}

func TestGAP1529ScanCodeOfAGuardedRootFailsPromptly(t *testing.T) {
	root, _ := tccTree(t)
	guardFolder(t, root)
	start := time.Now()
	_, err := ScanCode(context.Background(), root, "")
	if !errors.Is(err, ErrIncompleteScan) || !errors.Is(err, errFolderPrivacyProtected) {
		t.Fatalf("ScanCode: err = %v, want incomplete scan naming privacy protection", err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("ScanCode took %s", d)
	}
}

func TestGAP1529AQuickEINTRIsASignalAndIsRetried(t *testing.T) {
	oldOpen := rawOpenDir
	t.Cleanup(func() { rawOpenDir = oldOpen })
	n := 0
	rawOpenDir = func(string) error {
		n++
		if n < 3 {
			return syscall.EINTR
		}
		return nil
	}
	if err := probeDirOpen(t.TempDir()); err != nil || n != 3 {
		t.Fatalf("probe = %v after %d opens, want nil after 3", err, n)
	}
	rawOpenDir = func(string) error { return syscall.EACCES }
	if err := probeDirOpen(t.TempDir()); err != nil {
		t.Fatalf("probe of a refused folder = %v, want nil (the walk reports it)", err)
	}
}
