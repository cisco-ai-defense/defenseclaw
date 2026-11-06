// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// REVIEW-gx053-12 MF1: the commit carries the import-done flag; a record an
// earlier round wrote (no flag) counts as done, so it never reopens the
// import window.
func TestUnixOpenCodeServicePortsImportDone(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := filepath.Join(root, UnixOpenCodeServicePortsFileName)
	if got, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || got.Exists || got.ImportDone {
		t.Fatalf("no record is the import window: %+v %v", got, err)
	}
	if err := WriteUnixOpenCodeServicePortsFull(path, UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"import_done": true`) {
		t.Fatalf("the commit has no import-done flag: %s %v", data, err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"ports":[{"uid":1001,"port":25001}]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || !got.Exists || !got.ImportDone || got.Ports[1001] != 25001 {
		t.Fatalf("an earlier round's record is not done: %+v %v", got, err)
	}
}

// REVIEW-gx053-12 MF2: an administrator's clear racing a guardian pass (the
// pass's read, plan and commit under the reconcile lock) is never lost, and
// the pass's own change is kept too.
func TestClearUnixOpenCodeContestedPortRacingAGuardianPass(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := filepath.Join(root, UnixOpenCodeServicePortsFileName)
	pass := func(uid int) error {
		unlock, err := LockUnixGuardianReconcile(context.Background(), root, 10*time.Second)
		if err != nil {
			return err
		}
		defer unlock()
		state, err := LoadUnixOpenCodeServicePortsFull(path)
		if err != nil {
			return err
		}
		time.Sleep(2 * time.Millisecond) // the plan
		state.Ports[uid] = 20000 + uid
		state.ImportDone = true
		return WriteUnixOpenCodeServicePortsFull(path, state)
	}
	for i := 0; i < 40; i++ {
		start := UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001, 1002: 25002},
			Contested: []UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}}}
		if err := WriteUnixOpenCodeServicePortsFull(path, start); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var passErr, clearErr error
		wg.Add(2)
		go func() { defer wg.Done(); passErr = pass(3000 + i) }()
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				time.Sleep(time.Millisecond) // the clear lands while the pass plans
			}
			_, clearErr = ClearUnixOpenCodeContestedPortLocked(path, 25003, "admin", time.Unix(int64(i+1), 0), 10*time.Second)
		}()
		wg.Wait()
		if passErr != nil || clearErr != nil {
			t.Fatalf("round %d: pass %v, clear %v", i, passErr, clearErr)
		}
		got, err := LoadUnixOpenCodeServicePortsFull(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Contested) != 0 || len(got.Cleared) != 1 || got.Cleared[0].Port != 25003 {
			t.Fatalf("round %d: the clear was lost: contested %+v, cleared %+v", i, got.Contested, got.Cleared)
		}
		if got.Ports[3000+i] != 23000+i {
			t.Fatalf("round %d: the pass's change was lost: %v", i, got.Ports)
		}
	}
}
