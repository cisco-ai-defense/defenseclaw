// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func TestPublishHookAPITokenPublishesPrivateExactBytesAndPreservesNoopIdentity(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	token := strings.Repeat("a", 64)
	if err := PublishHookAPIToken(dataDir, "amp", token); err != nil {
		t.Fatalf("PublishHookAPIToken: %v", err)
	}
	path, err := HookAPITokenFilePath(dataDir, "amp")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw), token+"\n"; got != want {
		t.Fatalf("published token bytes = %q, want exact token plus newline", got)
	}
	if err := otlpValidatePerm(path, before); err != nil {
		t.Fatalf("published token is not private: %v", err)
	}
	if err := PublishHookAPIToken(dataDir, "amp", token); err != nil {
		t.Fatalf("PublishHookAPIToken no-op: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("no-op publication churned token identity or mtime: before=%v after=%v", before.ModTime(), after.ModTime())
	}

	bad := "not-a-valid-scoped-secret"
	if err := PublishHookAPIToken(dataDir, "amp", bad); err == nil {
		t.Fatal("PublishHookAPIToken malformed token error = nil")
	} else if strings.Contains(err.Error(), bad) {
		t.Fatalf("malformed-token error exposed supplied bytes: %v", err)
	}
}

func TestPublishHookAPITokenRestoresExistingTokenAfterPostPublicationFailure(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	oldToken := strings.Repeat("a", 64)
	newToken := strings.Repeat("b", 64)
	if err := PublishHookAPIToken(dataDir, "amp", oldToken); err != nil {
		t.Fatalf("seed old token: %v", err)
	}
	originalPublisher := publishHookAPITokenFile
	publishHookAPITokenFile = func(source, destination string, info os.FileInfo, mode os.FileMode) error {
		if err := atomicFilePublishHookAPIToken(source, destination, info, mode); err != nil {
			return err
		}
		return errors.New("injected failure after publication")
	}
	t.Cleanup(func() { publishHookAPITokenFile = originalPublisher })

	err := PublishHookAPIToken(dataDir, "amp", newToken)
	if err == nil || !strings.Contains(err.Error(), "injected failure after publication") {
		t.Fatalf("PublishHookAPIToken error = %v, want injected failure", err)
	}
	if strings.Contains(err.Error(), oldToken) || strings.Contains(err.Error(), newToken) {
		t.Fatalf("publication error exposed a scoped token: %v", err)
	}
	got, loadErr := LoadHookAPIToken(dataDir, "amp")
	if loadErr != nil || got != oldToken {
		t.Fatalf("token after failed publication = %q, %v; want restored old token", got, loadErr)
	}
}

func TestPublishHookAPITokenRestoresAbsenceAfterPostPublicationFailure(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	newToken := strings.Repeat("b", 64)
	originalPublisher := publishHookAPITokenFile
	publishHookAPITokenFile = func(source, destination string, info os.FileInfo, mode os.FileMode) error {
		if err := atomicFilePublishHookAPIToken(source, destination, info, mode); err != nil {
			return err
		}
		return errors.New("injected failure after publication")
	}
	t.Cleanup(func() { publishHookAPITokenFile = originalPublisher })

	err := PublishHookAPIToken(dataDir, "amp", newToken)
	if err == nil || !strings.Contains(err.Error(), "injected failure after publication") {
		t.Fatalf("PublishHookAPIToken error = %v, want injected failure", err)
	}
	path, pathErr := HookAPITokenFilePath(dataDir, "amp")
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication left a token behind: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication left its newly-created hooks directory behind: %v", err)
	}
}

func TestPublishHookAPITokenDoesNotOverwriteConcurrentReplacementDuringRollback(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	oldToken := strings.Repeat("a", 64)
	newToken := strings.Repeat("b", 64)
	concurrentToken := strings.Repeat("c", 64)
	if err := PublishHookAPIToken(dataDir, "amp", oldToken); err != nil {
		t.Fatalf("seed old token: %v", err)
	}
	originalPublisher := publishHookAPITokenFile
	publishHookAPITokenFile = func(source, destination string, info os.FileInfo, mode os.FileMode) error {
		if err := atomicFilePublishHookAPIToken(source, destination, info, mode); err != nil {
			return err
		}
		current, err := captureHookAPITokenPublishSnapshot(dataDir, destination)
		if err != nil {
			return err
		}
		if _, err := publishHookAPITokenBytes(
			dataDir,
			destination,
			[]byte(concurrentToken+"\n"),
			hookAPITokenPublishProtection{},
			current,
			atomicFilePublishHookAPIToken,
		); err != nil {
			return err
		}
		return errors.New("injected failure after concurrent replacement")
	}
	t.Cleanup(func() { publishHookAPITokenFile = originalPublisher })

	err := PublishHookAPIToken(dataDir, "amp", newToken)
	if err == nil || !strings.Contains(err.Error(), "changed before rollback") {
		t.Fatalf("PublishHookAPIToken error = %v, want concurrent-change refusal", err)
	}
	got, loadErr := LoadHookAPIToken(dataDir, "amp")
	if loadErr != nil || got != concurrentToken {
		t.Fatalf("token after concurrent replacement = %q, %v; want concurrent token preserved", got, loadErr)
	}
}

func TestPublishHookAPITokenWaitsForDataDirTransactionLock(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	lockPath := hookAPITokenPublishLockPath(dataDir)
	readyPath := filepath.Join(dataDir, "lock-helper-ready")
	releasePath := filepath.Join(dataDir, "lock-helper-release")
	command := exec.Command(os.Args[0], "-test.run=^TestPublishHookAPITokenTransactionLockHelper$")
	output := new(bytes.Buffer)
	command.Stdout = output
	command.Stderr = output
	command.Env = append(
		os.Environ(),
		"DEFENSECLAW_HOOK_TOKEN_LOCK_HELPER=1",
		"DEFENSECLAW_HOOK_TOKEN_LOCK_PATH="+lockPath,
		"DEFENSECLAW_HOOK_TOKEN_LOCK_READY="+readyPath,
		"DEFENSECLAW_HOOK_TOKEN_LOCK_RELEASE="+releasePath,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start transaction-lock helper: %v", err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- command.Wait() }()
	childExited := false
	var childWaitErr error
	waitForChild := func(timeout time.Duration) (error, bool) {
		if childExited {
			return childWaitErr, true
		}
		select {
		case childWaitErr = <-childDone:
			childExited = true
			return childWaitErr, true
		case <-time.After(timeout):
			return nil, false
		}
	}
	releaseHolder := func() {
		_ = os.WriteFile(releasePath, []byte("release"), 0o600)
	}

	publishDone := make(chan error, 1)
	publishStarted := false
	publishFinished := false
	var publishErr error
	waitForPublication := func(timeout time.Duration) (error, bool) {
		if publishFinished {
			return publishErr, true
		}
		select {
		case publishErr = <-publishDone:
			publishFinished = true
			return publishErr, true
		case <-time.After(timeout):
			return nil, false
		}
	}
	t.Cleanup(func() {
		// Release or terminate the cross-process holder before draining the
		// publication goroutine. This keeps every failure path bounded and
		// prevents a writer from outliving its temporary data directory.
		releaseHolder()
		if !childExited {
			if _, ok := waitForChild(2 * time.Second); !ok {
				if command.Process != nil {
					_ = command.Process.Kill()
				}
				if _, ok := waitForChild(5 * time.Second); !ok {
					t.Errorf("transaction-lock helper did not terminate during cleanup")
				}
			}
		}
		if publishStarted && !publishFinished {
			if err, ok := waitForPublication(45 * time.Second); !ok {
				t.Errorf("publication goroutine did not terminate during cleanup")
			} else if err != nil {
				t.Errorf("publication failed during cleanup: %v", err)
			}
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect transaction-lock helper readiness: %v", err)
		}
		if err, exited := waitForChild(10 * time.Millisecond); exited {
			t.Fatalf("transaction-lock helper exited before readiness: %v\n%s", err, output.String())
		}
		if time.Now().After(deadline) {
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			err, _ := waitForChild(5 * time.Second)
			t.Fatalf("timed out waiting for transaction-lock helper: %v\n%s", err, output.String())
		}
	}

	publishStarted = true
	go func() {
		publishDone <- PublishHookAPIToken(dataDir, "amp", strings.Repeat("d", 64))
	}()
	if err, finished := waitForPublication(150 * time.Millisecond); finished {
		t.Fatalf("publication completed while its data-directory transaction lock was held: %v", err)
	}
	if err := os.WriteFile(releasePath, []byte("release"), 0o600); err != nil {
		t.Fatalf("release test transaction lock: %v", err)
	}
	if err, exited := waitForChild(5 * time.Second); exited {
		if err != nil {
			t.Fatalf("transaction-lock helper after release: %v\n%s", err, output.String())
		}
	} else {
		t.Fatal("transaction-lock helper did not exit after release")
	}
	if err, finished := waitForPublication(45 * time.Second); finished {
		if err != nil {
			t.Fatalf("publication after lock release: %v", err)
		}
	} else {
		t.Fatal("publication did not complete after transaction-lock release")
	}
}

func TestPublishHookAPITokenTransactionLockHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_TOKEN_LOCK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	lockPath := os.Getenv("DEFENSECLAW_HOOK_TOKEN_LOCK_PATH")
	readyPath := os.Getenv("DEFENSECLAW_HOOK_TOKEN_LOCK_READY")
	releasePath := os.Getenv("DEFENSECLAW_HOOK_TOKEN_LOCK_RELEASE")
	if lockPath == "" || readyPath == "" || releasePath == "" {
		t.Fatal("transaction-lock helper environment is incomplete")
	}
	err := withOwnedFileLock(lockPath, func() error {
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			return err
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(releasePath); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if time.Now().After(deadline) {
				return errors.New("timed out waiting for transaction-lock release")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	if err != nil {
		t.Fatalf("hold transaction lock: %v", err)
	}
}
