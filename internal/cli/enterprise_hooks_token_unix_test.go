// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The standalone guardian has CAP_CHOWN but not CAP_FOWNER. Once the token
// belongs to the service account it can no longer chmod it (seen live on
// RHEL: every per-user repair failed with EPERM), so alignment must only
// chmod a wrong mode, and before the ownership hand-off.
func TestAlignScopedTokenSkipsChmodWhenModeIsAlreadyPrivate(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, "devin")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := enterpriseHookTokenChmod
	t.Cleanup(func() { enterpriseHookTokenChmod = previous })
	enterpriseHookTokenChmod = func(string, os.FileMode) error { return errors.New("operation not permitted") }
	if err := alignEnterpriseHookScopedTokenOwner(dataDir, "devin"); err != nil {
		t.Fatalf("aligning an already private token chmod-ed it: %v", err)
	}

	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	enterpriseHookTokenChmod = previous
	if err := alignEnterpriseHookScopedTokenOwner(dataDir, "devin"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %04o, want 0600", info.Mode().Perm())
	}
}
