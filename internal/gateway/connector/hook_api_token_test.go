// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func assertHookAPITokenRejectedByEnsureAndLoad(t *testing.T, want string, fixture func(*testing.T) string) {
	t.Helper()
	assertHookAPITokenRejectedByEnsureAndLoadAny(t, []string{want}, fixture)
}

func assertHookAPITokenRejectedByEnsureAndLoadAny(t *testing.T, wants []string, fixture func(*testing.T) string) {
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
			matched := false
			for _, want := range wants {
				if err != nil && strings.Contains(err.Error(), want) {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("hook token %s error = %v, want one of %q rejections", operation.name, err, wants)
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

func TestEnsureHookAPITokenDoesNotCreateHooksInUntrustedDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not available on Windows")
	}
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o777); err != nil {
		t.Fatalf("chmod data dir: %v", err)
	}
	if _, err := EnsureHookAPIToken(dataDir, "codex"); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("EnsureHookAPIToken error = %v, want trust rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hooks directory was created before trust validation: %v", err)
	}
}

func TestHookAPITokenRejectsSymlinkHooksDirectory(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoadAny(t, []string{"escapes hooks dir", "reparse points are not allowed"}, func(t *testing.T) string {
		dataDir := t.TempDir()
		targetDataDir := t.TempDir()
		if _, err := EnsureHookAPIToken(targetDataDir, "codex"); err != nil {
			t.Fatalf("seed target token: %v", err)
		}
		targetHooksDir := filepath.Join(targetDataDir, "hooks")
		createTestDirectoryRedirect(t, filepath.Join(dataDir, "hooks"), targetHooksDir)
		return dataDir
	})
}

func TestHookAPITokenRejectsSymlinkedDataDirParent(t *testing.T) {
	assertHookAPITokenRejectedByEnsureAndLoadAny(t, []string{"symlinks are not allowed", "reparse points are not allowed"}, func(t *testing.T) string {
		linkRoot := t.TempDir()
		targetRoot := t.TempDir()
		dataTarget := filepath.Join(targetRoot, "data")
		if err := os.Mkdir(dataTarget, 0o700); err != nil {
			t.Fatalf("mkdir target data dir: %v", err)
		}
		link := filepath.Join(linkRoot, "linked-parent")
		createTestDirectoryRedirect(t, link, targetRoot)
		return filepath.Join(link, "data")
	})
}

func TestLoadHookAPITokensSkipsAbsentFilesBeforeTrustValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not available on Windows")
	}
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o777); err != nil {
		t.Fatalf("chmod data dir: %v", err)
	}
	tokens, err := LoadHookAPITokens(dataDir, []string{"codex", "claudecode"})
	if err != nil {
		t.Fatalf("LoadHookAPITokens absent files: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("LoadHookAPITokens absent files = %v, want empty", tokens)
	}
}

func TestLoadHookAPITokensValidatesExistingFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not available on Windows")
	}
	dataDir := t.TempDir()
	if _, err := EnsureHookAPIToken(dataDir, "codex"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	hooksDir := filepath.Join(dataDir, "hooks")
	if err := os.Chmod(hooksDir, 0o777); err != nil {
		t.Fatalf("chmod hooks dir: %v", err)
	}
	if _, err := LoadHookAPITokens(dataDir, []string{"codex", "claudecode"}); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("LoadHookAPITokens existing file error = %v, want trust rejection", err)
	}
}

func TestConnectorHookWriterPreservesScopedAPITokenFormat(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	token, err := EnsureHookAPIToken(dataDir, "codex")
	if err != nil {
		t.Fatalf("EnsureHookAPIToken: %v", err)
	}
	if err := WriteHookScriptsForConnectorObject(filepath.Join(dataDir, "hooks"), "127.0.0.1:18970", token, NewCodexConnector()); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObject: %v", err)
	}
	scopedPath, err := HookAPITokenFilePath(dataDir, "codex")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	raw, err := os.ReadFile(scopedPath)
	if err != nil {
		t.Fatalf("read scoped token after hook write: %v", err)
	}
	if got, want := string(raw), token+"\n"; got != want {
		t.Fatalf("scoped token file contents = %q, want exact raw content %q", got, want)
	}
}
