//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const enterpriseCredentialLockHelperEnv = "GO_WANT_ACP_CREDENTIAL_LOCK_HELPER"

func TestEnterpriseCredentialMutationLockSerializesProcesses(t *testing.T) {
	if helperDir := os.Getenv(enterpriseCredentialLockHelperEnv); helperDir != "" {
		started := filepath.Join(helperDir, "started")
		acquired := filepath.Join(helperDir, "acquired")
		if err := os.WriteFile(started, []byte("started"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := withEnterpriseCredentialMutationLock(helperDir, func() error {
			return os.WriteFile(acquired, []byte("acquired"), 0o600)
		}); err != nil {
			t.Fatal(err)
		}
		return
	}

	dataDir := t.TempDir()
	var command *exec.Cmd
	var waited chan error
	err := withEnterpriseCredentialMutationLock(dataDir, func() error {
		command = exec.Command(os.Args[0], "-test.run=^TestEnterpriseCredentialMutationLockSerializesProcesses$")
		command.Env = append(os.Environ(), enterpriseCredentialLockHelperEnv+"="+dataDir)
		if err := command.Start(); err != nil {
			return err
		}
		waited = make(chan error, 1)
		go func() { waited <- command.Wait() }()
		started := filepath.Join(dataDir, "started")
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, statErr := os.Stat(started); statErr == nil {
				break
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
			if time.Now().After(deadline) {
				return errors.New("credential lock helper did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
		select {
		case childErr := <-waited:
			if childErr == nil {
				return errors.New("credential lock helper escaped the parent lock")
			}
			return childErr
		case <-time.After(200 * time.Millisecond):
		}
		if _, statErr := os.Stat(filepath.Join(dataDir, "acquired")); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("credential lock helper entered the protected transaction")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("credential lock helper failed after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("credential lock helper stayed blocked after release")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "acquired")); err != nil {
		t.Fatalf("credential lock helper did not enter after release: %v", err)
	}
}
