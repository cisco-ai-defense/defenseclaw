// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// managedRecoveryRoot is a folder a managed config can sit in. Linux trusts
// only a root-owned path, so the test needs root there; macOS has no such
// fixture and keeps the skip.
func managedRecoveryRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux: a managed config must sit on a root-owned path")
	}
	root, err := os.MkdirTemp("/var/lib", "dc-config-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// untrustedRulePackDir makes a rule pack folder a standard user owns, which a
// standalone managed config must refuse as a policy input.
func untrustedRulePackDir(t *testing.T, root string) string {
	t.Helper()
	pack := filepath.Join(root, "pack")
	if err := os.Mkdir(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(pack, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	return pack
}
