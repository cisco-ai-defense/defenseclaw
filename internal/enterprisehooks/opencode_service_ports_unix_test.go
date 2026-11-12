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
	if state, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || len(state.Ports) != 0 {
		t.Fatalf("a missing record is empty: %v %v", state.Ports, err)
	}
	if err := WriteUnixOpenCodeServicePortsFull(path, UnixOpenCodeServicePortsState{Ports: map[int]int{1002: 25002, 1001: 25001, 0: 1, 1003: 70000}, Users: map[int]string{1001: "ent1"}, ImportDone: true}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %o, want 0600", info.Mode().Perm())
	}
	got, err := LoadUnixOpenCodeServicePortsFull(path)
	if err != nil || len(got.Ports) != 2 || got.Ports[1001] != 25001 || got.Ports[1002] != 25002 {
		t.Fatalf("round trip must keep valid entries only: %v %v", got.Ports, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUnixOpenCodeServicePortsFull(path); err == nil {
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
		Contested: []UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}, {Port: 26000, UIDs: []int{1003, 1004}}}, ImportDone: true}
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

// REVIEW-gx053-13 S2: the import-done flag is read from the record. A record
// without the key (an earlier round's) is done; one committed with
// import_done false is not past its import pass, so the next pass is the
// import pass; a clear keeps the flag as it found it.
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
	for _, tc := range []struct {
		name string
		body string
		done bool
	}{
		{"no key (an earlier round)", `{"version":1,"ports":[{"uid":1001,"port":25001}]}`, true},
		{"true", `{"version":1,"import_done":true,"ports":[{"uid":1001,"port":25001}]}`, true},
		{"false", `{"version":1,"import_done":false,"ports":[{"uid":1001,"port":25001}]}`, false},
	} {
		if err := os.WriteFile(path, []byte(tc.body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadUnixOpenCodeServicePortsFull(path)
		if err != nil || !got.Exists || got.ImportDone != tc.done || got.Ports[1001] != 25001 {
			t.Fatalf("%s: import done %v, want %v: %+v %v", tc.name, got.ImportDone, tc.done, got, err)
		}
	}
	// The writer commits the flag it is given, and a clear keeps it.
	pending := UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001}, Contested: []UnixOpenCodeContestedPort{{Port: 26000, UIDs: []int{1001, 1002}}}}
	if err := WriteUnixOpenCodeServicePortsFull(path, pending); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || got.ImportDone {
		t.Fatalf("a record committed pending reads done: %+v %v", got, err)
	}
	if _, err := ClearUnixOpenCodeContestedPort(path, 26000, "admin", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || got.ImportDone || len(got.Contested) != 0 {
		t.Fatalf("a clear changed the flag: %+v %v", got, err)
	}
	pending.ImportDone = true
	if err := WriteUnixOpenCodeServicePortsFull(path, pending); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"import_done": true`) {
		t.Fatalf("the commit has no import-done flag: %s %v", data, err)
	}
	if got, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || !got.ImportDone {
		t.Fatalf("a record committed done reads pending: %+v %v", got, err)
	}
}

// REVIEW-gx053-13 S2: a killed record write leaves its temp file; a later pass
// (holding the reconcile lock) sweeps the files older than the pass start,
// from the record's own folder only, and never a live writer's file.
func TestSweepUnixOpenCodeServicePortsTemp(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := filepath.Join(root, UnixOpenCodeServicePortsFileName)
	if err := WriteUnixOpenCodeServicePortsFull(path, UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001}, ImportDone: true}); err != nil {
		t.Fatal(err)
	}
	write := func(dir, name string, age time.Duration) string {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte("{\"version\":1,"), 0o600); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(full, when, when); err != nil {
			t.Fatal(err)
		}
		return full
	}
	orphan1 := write(root, ".defenseclaw-opencode-ports-123456.new", time.Hour)
	orphan2 := write(root, ".defenseclaw-opencode-ports-7.new", 3*time.Minute)
	otherRecord := write(root, ".defenseclaw-copilot-vscode-accounts-123.new", time.Hour) // another record's temp
	unrelated := write(root, "notes.new", time.Hour)
	lookalike := write(root, ".defenseclaw-opencode-ports-1.new.keep", time.Hour)
	subdir := filepath.Join(root, "sub")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := write(subdir, ".defenseclaw-opencode-ports-9.new", time.Hour) // another folder
	dirNamed := filepath.Join(root, ".defenseclaw-opencode-ports-55.new")   // a folder, not a file
	if err := os.Mkdir(dirNamed, 0o700); err != nil {
		t.Fatal(err)
	}
	linkTarget := write(root, "target.txt", time.Hour)
	link := filepath.Join(root, ".defenseclaw-opencode-ports-77.new")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}
	// A writer at work under the guardian lock: its temp file is new (after
	// the pass start), so the sweep keeps it, and the committed record.
	passStart := time.Now().Add(-time.Minute)
	unlock, err := LockUnixGuardianReconcile(context.Background(), root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	live := write(root, ".defenseclaw-opencode-ports-999.new", 0)
	removed, err := SweepUnixOpenCodeServicePortsTemp(path, passStart)
	unlock()
	if err != nil || removed != 2 {
		t.Fatalf("removed %d, want the 2 orphans: %v", removed, err)
	}
	for _, gone := range []string{orphan1, orphan2} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("the orphan %s is still there: %v", gone, err)
		}
	}
	for _, kept := range []string{live, otherRecord, unrelated, lookalike, nested, dirNamed, link, linkTarget, path} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("%s must stay: %v", kept, err)
		}
	}
	if got, err := LoadUnixOpenCodeServicePortsFull(path); err != nil || got.Ports[1001] != 25001 {
		t.Fatalf("the record changed: %+v %v", got, err)
	}
	// The live writer finishes its commit after the sweep: the real writer
	// still works beside the kept file.
	if err := WriteUnixOpenCodeServicePortsFull(path, UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001, 1002: 25002}, ImportDone: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(live); err != nil {
		t.Fatalf("the writer's commit removed a live file: %v", err)
	}
	// A pass that starts later sees that file as an orphan.
	if removed, err := SweepUnixOpenCodeServicePortsTemp(path, time.Now().Add(time.Minute)); err != nil || removed != 1 {
		t.Fatalf("a later pass removed %d, want the 1 file left: %v", removed, err)
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
			Contested: []UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}}, ImportDone: true}
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

// GAP-0904: the removal of a stale unknown entry changes nothing else, and
// refuses while the uid still has an account, when the check does not answer
// and when the uid is not listed.
func TestClearUnixOpenCodeUnknownLockedRefusesALiveUID(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		t.Skipf("test directory chain cannot hold the record: %v", err)
	}
	path := filepath.Join(root, UnixOpenCodeServicePortsFileName)
	state := UnixOpenCodeServicePortsState{Ports: map[int]int{1001: 25001, 1234: 25002}, Users: map[int]string{1234: "gone"},
		Unknown:   []UnixOpenCodeServicePortUnknown{{UID: 1001, User: "live", Reason: "r"}, {UID: 1234, User: "gone", Reason: "r"}},
		Contested: []UnixOpenCodeContestedPort{{Port: 26000, UIDs: []int{1003, 1004}}}, ImportDone: true}
	if err := WriteUnixOpenCodeServicePortsFull(path, state); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	answer := func(has bool, err error) func(int) (bool, error) {
		return func(int) (bool, error) { return has, err }
	}
	for name, run := range map[string]func() error{
		"live uid": func() error {
			_, err := ClearUnixOpenCodeUnknownLocked(path, 1234, time.Second, answer(true, nil))
			return err
		},
		"lookup fails": func() error {
			_, err := ClearUnixOpenCodeUnknownLocked(path, 1234, time.Second, answer(false, os.ErrDeadlineExceeded))
			return err
		},
		"uid is not listed": func() error {
			_, err := ClearUnixOpenCodeUnknownLocked(path, 4321, time.Second, answer(false, nil))
			return err
		},
	} {
		if err := run(); err == nil {
			t.Fatalf("%s: the removal was not refused", name)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Fatalf("%s: a refused removal changed the record", name)
		}
	}
	removed, err := ClearUnixOpenCodeUnknownLocked(path, 1234, time.Second, answer(false, nil))
	if err != nil || removed.User != "gone" {
		t.Fatalf("removal: %+v %v", removed, err)
	}
	got, err := LoadUnixOpenCodeServicePortsFull(path)
	if err != nil || len(got.Unknown) != 1 || got.Unknown[0].UID != 1001 || got.Ports[1234] != 25002 || len(got.Contested) != 1 || !got.ImportDone {
		t.Fatalf("after removal: %+v %v", got, err)
	}
}
