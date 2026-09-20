// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestInspectCodexPolicyRequiresFreshSetupSelectionBeforeMutation(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	_, err := inspectCodexEffectivePolicy(context.Background(), SetupOpts{DataDir: dir})
	if err == nil || !strings.Contains(err.Error(), "setup-selected native executable") {
		t.Fatalf("fresh Windows policy inspection error = %v, want setup-selection refusal", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, hookContractLockFile)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed inspection mutated hook lock: %v", statErr)
	}
}

func TestCodexSetupWithoutSelectionLeavesRegistrationAndArtifactsUntouched(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	configPath := filepath.Join(t.TempDir(), ".codex", "config.toml")
	originalInspector := codexPolicyInspector
	codexPolicyInspector = inspectCodexEffectivePolicy
	t.Cleanup(func() { codexPolicyInspector = originalInspector })
	originalConfigPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = originalConfigPath })

	err := NewCodexConnector().Setup(context.Background(), SetupOpts{
		DataDir:      dir,
		HookFailMode: "closed",
	})
	if err == nil || !strings.Contains(err.Error(), "setup-selected native executable") {
		t.Fatalf("fresh Windows Codex setup error = %v, want setup-selection refusal", err)
	}
	for _, path := range []string{
		configPath,
		filepath.Join(dir, "hooks"),
		filepath.Join(dir, "backups"),
		filepath.Join(dir, hookContractLockFile),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed Codex setup mutated %s: %v", path, statErr)
		}
	}
}

func TestStartCodexAppServerTreeAssignsBeforeImmediateGrandchild(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "wrapper-entered")
	ready := filepath.Join(root, "grandchild-ready")
	marker := filepath.Join(root, "grandchild-survived")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCodexPolicyAppServerHelper$", "--")
	cmd.Env = append(
		os.Environ(),
		codexPolicyTreeHelperEnv+"=1",
		codexPolicyEntryPathEnv+"="+entry,
		codexPolicyReadyPathEnv+"="+ready,
		codexPolicyMarkerPathEnv+"="+marker,
	)

	cleanup, err := startCodexAppServerTreeObserved(cmd, func() error {
		time.Sleep(250 * time.Millisecond)
		if _, err := os.Stat(entry); err == nil {
			return errors.New("wrapper executed before job assignment")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect wrapper entry marker: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("start contained app-server tree: %v", err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			cleanup()
		}
	}()

	waitForCodexPolicyMarker(t, ready, 3*time.Second)
	cancel()
	cleanup()
	cleanup() // cleanup ownership is deliberately idempotent.
	cleaned = true
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("immediate app-server grandchild escaped the assigned job (stat: %v)", err)
	}
}

func TestValidateCodexPolicyExecutableRejectsCommandProcessorWrapper(t *testing.T) {
	root := t.TempDir()
	wrapper := filepath.Join(root, "codex.cmd")
	if err := os.WriteFile(wrapper, []byte("@echo off\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := validateCodexPolicyExecutable(SetupOpts{AgentExecutable: wrapper})
	if err == nil || !strings.Contains(err.Error(), "native Windows .exe") {
		t.Fatalf("batch-wrapper validation error = %v, want native-image refusal", err)
	}
}

func waitForCodexPolicyMarker(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
