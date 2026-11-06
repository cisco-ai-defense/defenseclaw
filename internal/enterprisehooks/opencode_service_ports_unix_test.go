// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

// gas-ux-r1 GAP-0053: the guardian's OpenCode service ports record is
// root-only like the eligible accounts record and round-trips the ports.
func TestUnixOpenCodeServicePortsRoundTripAndTrust(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := filepath.Join(root, UnixOpenCodeServicePortsFileName)
	if ports, err := LoadUnixOpenCodeServicePorts(path); err != nil || len(ports) != 0 {
		t.Fatalf("a missing record is empty: %v %v", ports, err)
	}
	if err := WriteUnixOpenCodeServicePorts(path, map[int]int{1002: 25002, 1001: 25001, 0: 1, 1003: 70000}, map[int]string{1001: "ent1"}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %o, want 0600", info.Mode().Perm())
	}
	got, err := LoadUnixOpenCodeServicePorts(path)
	if err != nil || len(got) != 2 || got[1001] != 25001 || got[1002] != 25002 {
		t.Fatalf("round trip must keep valid entries only: %v %v", got, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUnixOpenCodeServicePorts(path); err == nil {
		t.Fatal("a record others can read must be refused")
	}
}
