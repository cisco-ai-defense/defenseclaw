//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"syscall"
	"testing"
)

// Root changes the service-side ACP credentials as the owner of the managed
// data_dir, so the gateway account keeps owning its credential directory
// and a second enrollment is not refused (GAP-0251).
func TestEnterpriseACPServiceChangesRunAsTheDataDirOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a root test run owns its temporary data_dir")
	}
	restoreEUID, restoreRun := enterpriseACPEUID, enterpriseACPRunAsAccount
	t.Cleanup(func() { enterpriseACPEUID, enterpriseACPRunAsAccount = restoreEUID, restoreRun })
	enterpriseACPEUID = func() int { return 0 }
	var ranAs []int
	enterpriseACPRunAsAccount = func(uid, gid int, fn func() error) error {
		ranAs = append(ranAs, uid, gid)
		return fn()
	}
	dataDir := t.TempDir()
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	ran := false
	if err := withEnterpriseACPServiceOwner(dataDir, func() error { ran = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ran || len(ranAs) != 2 || ranAs[0] != int(owner.Uid) || ranAs[1] != int(owner.Gid) {
		t.Fatalf("ran=%v as %v, want the change run as the data_dir owner %d:%d", ran, ranAs, owner.Uid, owner.Gid)
	}
}
