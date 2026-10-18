//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// secureClientChain returns a root-owned, not group/other-writable directory
// directly below a root-owned, group-writable /opt/cisco/secureclient, the
// layout Cisco Secure Client installs on macOS. Hosts without it skip.
func secureClientChain(t *testing.T) (parent, leaf string) {
	t.Helper()
	parent = "/opt/cisco/secureclient"
	info, err := os.Stat(parent)
	if err != nil {
		t.Skipf("%s not present: %v", parent, err)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || info.Mode().Perm()&0o022 == 0 {
		t.Skipf("%s is not a root-owned, group/other-writable directory", parent)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Skipf("read %s: %v", parent, err)
	}
	for _, entry := range entries {
		candidate := filepath.Join(parent, entry.Name())
		child, err := os.Lstat(candidate)
		if err != nil || !child.IsDir() || child.Mode().Perm()&0o022 != 0 {
			continue
		}
		if st, ok := child.Sys().(*syscall.Stat_t); ok && st.Uid == 0 {
			return parent, candidate
		}
	}
	t.Skipf("no root-owned, non-writable directory below %s", parent)
	return "", ""
}

func TestValidateRootOwnedDirChainTreatsSecureClientAncestorsAsAdvisory(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	parent, leaf := secureClientChain(t)
	if err := validateRootOwnedDirChain(leaf); err != nil {
		t.Fatalf("validateRootOwnedDirChain(%s) = %v, want nil (ancestor %s is installer-owned)", leaf, err, parent)
	}
	// The directory asked about is never relaxed.
	if err := validateRootOwnedDirChain(parent); err == nil {
		t.Fatalf("validateRootOwnedDirChain(%s) = nil, want the group/other-writable leaf to stay fatal", parent)
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if err := validateRootOwnedDirChain(leaf); err == nil {
		t.Fatalf("validateRootOwnedDirChain(%s) with %s=1 = nil, want the ancestor verdict fatal", leaf, managed.TrustStrictAncestorsEnv)
	}
}
