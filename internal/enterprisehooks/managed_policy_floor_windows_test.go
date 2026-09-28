//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"testing"
)

// The version floor shares the Claude Code managed policy lock, and only a
// standalone process may take it for that purpose.
func TestWithWindowsClaudeManagedPolicyTransactionIsStandaloneOnly(t *testing.T) {
	previousStandalone := windowsEnterpriseStandaloneProcess
	previousTransaction := windowsClaudeManagedPolicyTransaction
	previousPath := windowsClaudeManagedPolicyPathResolver
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsClaudeManagedPolicyTransaction = previousTransaction
		windowsClaudeManagedPolicyPathResolver = previousPath
	})
	dir := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.d")
	windowsClaudeManagedPolicyPathResolver = func() (string, error) {
		return filepath.Join(dir, windowsClaudeManagedPolicyFile), nil
	}
	locked := 0
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error {
		locked++
		return fn()
	}

	windowsEnterpriseStandaloneProcess = func() bool { return false }
	called := false
	if err := WithWindowsClaudeManagedPolicyTransaction(func(string) error { called = true; return nil }); err == nil || called || locked != 0 {
		t.Fatalf("a Secure Client process must be refused before the lock: err=%v called=%v locked=%d", err, called, locked)
	}

	windowsEnterpriseStandaloneProcess = func() bool { return true }
	got := ""
	if err := WithWindowsClaudeManagedPolicyTransaction(func(policyDir string) error { got = policyDir; return nil }); err != nil {
		t.Fatal(err)
	}
	if got != dir || locked != 1 {
		t.Fatalf("policy dir = %q (want %q), locked %d times", got, dir, locked)
	}
}
