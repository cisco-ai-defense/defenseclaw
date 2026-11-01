//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2432: a <policy_dir>/guardrail folder the gateway service account
// cannot list (a root shell under umask 077 made it 0700) refused every
// reload with only "open <folder>: permission denied". The refusal names the
// folder, its mode and the fix, and still wraps the permission error.
func TestGAP2432UnlistableGuardrailFolderNamesModeAndFix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test needs an unprivileged account, which cannot list a folder without read permission")
	}
	root := t.TempDir()
	guardrail := filepath.Join(root, "guardrail")
	if err := os.MkdirAll(filepath.Join(guardrail, "my-pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Search but no read: even the owner cannot list it.
	if err := os.Chmod(guardrail, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(guardrail, 0o755) })
	previous := managedPolicyTreeChecks
	pass := func(string, string, string) error { return nil }
	managedPolicyTreeChecks = policyTreeChecks{dir: pass, file: pass, tree: pass}
	t.Cleanup(func() { managedPolicyTreeChecks = previous })

	err := ValidateManagedPolicyDir(&Config{PolicyDir: root}, root, "")
	if err == nil {
		t.Fatal("an unlistable guardrail folder passed the policy_dir check")
	}
	for _, want := range []string{
		guardrail + " is 0300 owned by ",
		"service account cannot read the policy_dir below it",
		"chmod 0750 " + guardrail,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err, want)
		}
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error %v no longer wraps the permission error", err)
	}
}
