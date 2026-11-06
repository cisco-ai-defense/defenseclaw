// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if err := WriteUnixOpenCodeServicePorts(path, map[int]int{1002: 25002, 1001: 25001, 0: 1, 1003: 70000}, map[int]string{1001: "ent1"}, nil); err != nil {
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

// The clear removes only the named mark, keeps every binding and logs it.
func TestClearUnixOpenCodeContestedPort(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := filepath.Join(root, UnixOpenCodeServicePortsFileName)
	state := UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001, 1002: 25002}, Users: map[int]string{1001: "a"},
		Contested: []UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}, {Port: 26000, UIDs: []int{1003, 1004}}}}
	if err := WriteUnixOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	if _, err := ClearUnixOpenCodeContestedPort(path, 27000, "admin", time.Now()); err == nil {
		t.Fatal("a port that is not marked was cleared")
	}
	uids, err := ClearUnixOpenCodeContestedPort(path, 25003, "admin", time.Unix(1, 0))
	if err != nil || len(uids) != 2 {
		t.Fatalf("clear: %v %v", uids, err)
	}
	got, err := LoadUnixOpenCodeServicePortsFull(path)
	if err != nil || len(got.Contested) != 1 || got.Contested[0].Port != 26000 || got.Ports[1001] != 25001 || got.Ports[1002] != 25002 {
		t.Fatalf("after clear: %+v %v", got, err)
	}
	if len(got.Cleared) != 1 || got.Cleared[0].Port != 25003 || got.Cleared[0].By != "admin" || got.Users[1001] != "a" {
		t.Fatalf("the clear is not logged: %+v", got.Cleared)
	}
}
