// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func assertHookAPITokenRejectedByEnsureAndLoad(t *testing.T, want string, fixture func(*testing.T) string) {
	t.Helper()
	operations := []struct {
		name string
		run  func(string) (string, error)
	}{
		{name: "ensure", run: func(dataDir string) (string, error) { return EnsureHookAPIToken(dataDir, "codex") }},
		{name: "load", run: func(dataDir string) (string, error) { return LoadHookAPIToken(dataDir, "codex") }},
		{name: "read", run: func(dataDir string) (string, error) {
			path, err := HookAPITokenFilePath(dataDir, "codex")
			if err != nil {
				return "", err
			}
			return readSecureHookAPITokenFile(dataDir, path)
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			dataDir := fixture(t)
			_, err := operation.run(dataDir)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("hook token %s error = %v, want %q rejection", operation.name, err, want)
			}
		})
	}
}

func TestHookAPITokenRejectsWritableHooksDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not available on Windows")
	}
	assertHookAPITokenRejectedByEnsureAndLoad(t, "not trusted", func(t *testing.T) string {
		dataDir := t.TempDir()
		hooksDir := filepath.Join(dataDir, "hooks")
		if err := os.Mkdir(hooksDir, 0o700); err != nil {
			t.Fatalf("mkdir hooks: %v", err)
		}
		if err := os.Chmod(hooksDir, 0o777); err != nil {
			t.Fatalf("chmod hooks: %v", err)
		}
		return dataDir
	})
}

func TestHookAPITokenRejectsSymlinkHooksDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}
	assertHookAPITokenRejectedByEnsureAndLoad(t, "escapes hooks dir", func(t *testing.T) string {
		dataDir := t.TempDir()
		targetDataDir := t.TempDir()
		if _, err := EnsureHookAPIToken(targetDataDir, "codex"); err != nil {
			t.Fatalf("seed target token: %v", err)
		}
		targetHooksDir := filepath.Join(targetDataDir, "hooks")
		if err := os.Symlink(targetHooksDir, filepath.Join(dataDir, "hooks")); err != nil {
			t.Fatalf("symlink hooks: %v", err)
		}
		return dataDir
	})
}

func TestHookAPITokenRejectsSymlinkedDataDirParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}
	assertHookAPITokenRejectedByEnsureAndLoad(t, "symlinks are not allowed", func(t *testing.T) string {
		linkRoot := t.TempDir()
		targetRoot := t.TempDir()
		dataTarget := filepath.Join(targetRoot, "data")
		if err := os.Mkdir(dataTarget, 0o700); err != nil {
			t.Fatalf("mkdir target data dir: %v", err)
		}
		link := filepath.Join(linkRoot, "linked-parent")
		if err := os.Symlink(targetRoot, link); err != nil {
			t.Fatalf("symlink parent: %v", err)
		}
		return filepath.Join(link, "data")
	})
}
