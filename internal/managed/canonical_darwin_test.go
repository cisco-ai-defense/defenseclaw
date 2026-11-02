//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAssessDarwinObject(t *testing.T) {
	form := darwinCanonicalForm{UID: 0, GID: darwinGIDWheel, Mode: 0o640}
	notAdmin := func(uint32) bool { return false }
	isAdmin := func(uid uint32) bool { return uid == 501 }
	cases := []struct {
		name          string
		state         darwinObjectState
		admin         func(uint32) bool
		wantOutcome   CanonicalOutcome
		wantUntrusted []string
	}{
		{name: "canonical", state: darwinObjectState{Mode: 0o640}, wantOutcome: CanonicalOK},
		{name: "tighter mode", state: darwinObjectState{Mode: 0o600}, wantOutcome: CanonicalOK},
		{name: "root:admin", state: darwinObjectState{GID: darwinGIDAdmin, Mode: 0o640}, wantOutcome: CanonicalOK},
		{name: "hidden and nodump", state: darwinObjectState{Mode: 0o640, Flags: unix.UF_HIDDEN | unix.UF_NODUMP}, wantOutcome: CanonicalOK},
		{name: "group write wheel", state: darwinObjectState{Mode: 0o660}, wantOutcome: CanonicalAccepted},
		{name: "group write staff", state: darwinObjectState{GID: darwinGIDStaff, Mode: 0o660}, wantOutcome: CanonicalBoundary, wantUntrusted: []string{"group:20"}},
		{name: "other write", state: darwinObjectState{Mode: 0o642}, wantOutcome: CanonicalBoundary, wantUntrusted: []string{"other"}},
		{name: "owner lacks read", state: darwinObjectState{Mode: 0o040}, wantOutcome: CanonicalAccepted},
		{name: "uchg", state: darwinObjectState{Mode: 0o640, Flags: unix.UF_IMMUTABLE}, wantOutcome: CanonicalAccepted},
		{name: "admin owner", state: darwinObjectState{UID: 501, Mode: 0o640}, admin: isAdmin, wantOutcome: CanonicalAccepted},
		{name: "user owner", state: darwinObjectState{UID: 502, Mode: 0o640}, wantOutcome: CanonicalBoundary},
		{name: "admin ACL", state: darwinObjectState{Mode: 0o640, ACL: darwinACLJudgement{Entries: 1}}, wantOutcome: CanonicalAccepted},
		{
			name:        "untrusted ACL",
			state:       darwinObjectState{Mode: 0o640, ACL: darwinACLJudgement{Entries: 1, UntrustedWriters: []string{"group:everyone"}}},
			wantOutcome: CanonicalBoundary, wantUntrusted: []string{"acl:group:everyone"},
		},
		{name: "unreadable ACL", state: darwinObjectState{Mode: 0o640, ACLError: "timed out"}, wantOutcome: CanonicalAccepted},
		{name: "setuid", state: darwinObjectState{Mode: 0o640 | unix.S_ISUID}, wantOutcome: CanonicalAccepted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admin := tc.admin
			if admin == nil {
				admin = notAdmin
			}
			a := assessDarwinObject(tc.state, form, admin)
			if got := a.outcome(); got != tc.wantOutcome {
				t.Fatalf("outcome = %s, want %s (drift %v)", got, tc.wantOutcome, a.Drift)
			}
			if tc.wantUntrusted != nil && strings.Join(a.UntrustedWriters, ",") != strings.Join(tc.wantUntrusted, ",") {
				t.Fatalf("untrusted = %v, want %v", a.UntrustedWriters, tc.wantUntrusted)
			}
			if tc.wantOutcome != CanonicalOK && len(a.Drift) == 0 {
				t.Fatal("drift is empty for a non-canonical object")
			}
		})
	}
}

func TestDarwinRepairModeKeepsTighterGroupOther(t *testing.T) {
	form := darwinCanonicalForm{Mode: 0o750}
	cases := map[uint32]os.FileMode{0o777: 0o750, 0o700: 0o700, 0o000: 0o700, 0o710: 0o710, 0o4755: 0o750}
	for current, want := range cases {
		if got := darwinRepairMode(current, form); got != want {
			t.Errorf("darwinRepairMode(%04o) = %04o, want %04o", current, got, want)
		}
	}
}

// selfOwnedOptions points the canonical form at the test user, so the repair
// path runs unprivileged.
func selfOwnedOptions(mode os.FileMode) CanonicalOptions {
	return CanonicalOptions{
		UnixOwner: &UnixOwnership{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())},
		UnixMode:  mode,
	}
}

func captureResilienceEvents(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	previous := ReportResilienceEvent
	ReportResilienceEvent = func(marker string, fields map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, FormatResilienceEvent(marker, fields))
	}
	advisoryLogDedupe.reset()
	t.Cleanup(func() {
		ReportResilienceEvent = previous
		advisoryLogDedupe.reset()
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func TestEnsureCanonicalDarwinRepairsDrift(t *testing.T) {
	drifts := []struct {
		name  string
		apply func(t *testing.T, path string)
	}{
		{name: "group write", apply: func(t *testing.T, path string) { mustChmod(t, path, 0o660) }},
		{name: "other write", apply: func(t *testing.T, path string) { mustChmod(t, path, 0o646) }},
		{name: "explicit write ACL", apply: func(t *testing.T, path string) { addDarwinACL(t, path, "everyone allow write,append") }},
		{name: "read ACL", apply: func(t *testing.T, path string) { addDarwinACL(t, path, "everyone allow read") }},
		{name: "uchg", apply: func(t *testing.T, path string) { mustChflags(t, path, "uchg") }},
		{name: "uappnd", apply: func(t *testing.T, path string) { mustChflags(t, path, "uappnd") }},
		{name: "owner lacks write", apply: func(t *testing.T, path string) { mustChmod(t, path, 0o400) }},
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			events := captureResilienceEvents(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
				t.Fatal(err)
			}
			mustChmod(t, path, 0o640)
			t.Cleanup(func() { _ = exec.Command("/usr/bin/chflags", "nouchg,nouappnd", path).Run() })
			drift.apply(t, path)

			result, err := EnsureCanonical(path, ObjectConfigFile, selfOwnedOptions(0o640))
			if err != nil {
				t.Fatalf("EnsureCanonical: %v", err)
			}
			if result.Outcome != CanonicalRepaired {
				t.Fatalf("outcome = %s, want repaired (drift %v, repair error %q)", result.Outcome, result.Drift, result.RepairError)
			}
			again, _ := AssessCanonical(path, ObjectConfigFile, selfOwnedOptions(0o640))
			if again.Outcome != CanonicalOK {
				t.Fatalf("after repair outcome = %s, drift %v", again.Outcome, again.Drift)
			}
			if got := events(); len(got) != 1 || !strings.HasPrefix(got[0], MarkerRepair+" ") {
				t.Fatalf("events = %q, want one %s line", got, MarkerRepair)
			}
		})
	}
}

func TestEnsureCanonicalDarwinRepairsInheritedACL(t *testing.T) {
	events := captureResilienceEvents(t)
	parent := t.TempDir()
	// macOS applies a parent's inheritable entry to a file when it is
	// created; the file then carries an "inherited" write entry.
	addDarwinACL(t, parent, "everyone allow write,file_inherit")
	path := filepath.Join(parent, "config.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, path, 0o640)
	before, _ := AssessCanonical(path, ObjectConfigFile, selfOwnedOptions(0o640))
	if before.Outcome != CanonicalBoundary {
		t.Fatalf("before outcome = %s, drift %v; want boundary for the inherited write entry", before.Outcome, before.Drift)
	}
	result, err := EnsureCanonical(path, ObjectConfigFile, selfOwnedOptions(0o640))
	if err != nil || result.Outcome != CanonicalRepaired {
		t.Fatalf("outcome = %s, err %v, repair error %q", result.Outcome, err, result.RepairError)
	}
	if got := events(); len(got) != 2 {
		t.Fatalf("events = %q, want one boundary and one repair line", got)
	}
}

func TestEnsureCanonicalDarwinAcceptsTighterModeAndHidden(t *testing.T) {
	events := captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustChflags(t, path, "hidden")
	result, err := EnsureCanonical(path, ObjectRuntimeFile, selfOwnedOptions(0o640))
	if err != nil || result.Outcome != CanonicalOK {
		t.Fatalf("outcome = %s, err %v, drift %v; want ok", result.Outcome, err, result.Drift)
	}
	if got := events(); len(got) != 0 {
		t.Fatalf("events = %q, want none", got)
	}
}

func TestEnsureCanonicalDarwinRepairsDirectory(t *testing.T) {
	captureResilienceEvents(t)
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, dir, 0o777)
	addDarwinACL(t, dir, "everyone allow add_file,delete_child,file_inherit,directory_inherit")
	result, err := EnsureCanonical(dir, ObjectRuntimeDirectory, selfOwnedOptions(0))
	if err != nil || result.Outcome != CanonicalRepaired {
		t.Fatalf("outcome = %s, err %v, repair error %q", result.Outcome, err, result.RepairError)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("mode = %04o, want 0750", info.Mode().Perm())
	}
}

func TestEnsureCanonicalDarwinNeverFollowsStructure(t *testing.T) {
	events := captureResilienceEvents(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, target, 0o666)

	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	result, err := EnsureCanonical(link, ObjectConfigFile, selfOwnedOptions(0o640))
	if err == nil || result.Outcome != CanonicalStructural {
		t.Fatalf("symlink outcome = %s, err %v; want structural", result.Outcome, err)
	}

	hard := filepath.Join(dir, "targets.yaml")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	result, err = EnsureCanonical(hard, ObjectAdminFile, selfOwnedOptions(0o640))
	if err == nil || result.Outcome != CanonicalStructural || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard link outcome = %s, err %v; want structural", result.Outcome, err)
	}

	result, err = EnsureCanonical(dir, ObjectConfigFile, selfOwnedOptions(0o640))
	if err == nil || result.Outcome != CanonicalStructural {
		t.Fatalf("wrong type outcome = %s, err %v; want structural", result.Outcome, err)
	}

	if info, _ := os.Stat(target); info.Mode().Perm() != 0o666 {
		t.Fatalf("link target mode changed to %04o", info.Mode().Perm())
	}
	if got := events(); len(got) != 3 {
		t.Fatalf("events = %q, want three boundary lines", got)
	}
	for _, line := range events() {
		if !strings.HasPrefix(line, MarkerBoundary+" ") {
			t.Fatalf("event %q is not a boundary line", line)
		}
	}

	missing, err := EnsureCanonical(filepath.Join(dir, "absent"), ObjectConfigFile, selfOwnedOptions(0o640))
	if err != nil || missing.Outcome != CanonicalMissing {
		t.Fatalf("missing outcome = %s, err %v", missing.Outcome, err)
	}
}

func TestEnsureCanonicalDarwinRefusesUntrustedOwner(t *testing.T) {
	captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	previous := darwinAdminMember
	darwinAdminMember = func(uint32) bool { return false }
	t.Cleanup(func() { darwinAdminMember = previous })
	// The canonical owner is a uid the test user is not, so the test user
	// is an untrusted owner.
	opts := CanonicalOptions{UnixOwner: &UnixOwnership{UID: uint32(os.Getuid()) + 1, GID: uint32(os.Getgid())}}
	result, err := EnsureCanonical(path, ObjectConfigFile, opts)
	if err != nil || result.Outcome != CanonicalBoundary || result.RepairError == "" {
		t.Fatalf("outcome = %s, err %v, repair error %q; want boundary without adoption", result.Outcome, err, result.RepairError)
	}
}

func TestMoveAsideStructuralLeavesTargetAlone(t *testing.T) {
	events := captureResilienceEvents(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "runtime")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	moved, err := MoveAsideStructural(link, "symlink")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(moved), "runtime.defenseclaw-moved-") {
		t.Fatalf("moved to %s", moved)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("link still present: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("target changed: %q %v", data, err)
	}
	if got := events(); len(got) != 1 || !strings.HasPrefix(got[0], MarkerBoundary+" ") {
		t.Fatalf("events = %q", got)
	}
}

func TestClassifyDenialDarwin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustChflags(t, path, "uchg")
	t.Cleanup(func() { _ = exec.Command("/usr/bin/chflags", "nouchg", path).Run() })
	err := os.Remove(path)
	if err == nil {
		t.Fatal("remove of an immutable file succeeded")
	}
	if got := ClassifyDenial(path, err); got != DenialFlags || !got.Drift() {
		t.Fatalf("ClassifyDenial(uchg) = %q, want flags", got)
	}
	if got := ClassifyDenial("/nonexistent/x", &os.PathError{Op: "open", Path: "/nonexistent/x", Err: unix.EPERM}); got != DenialPolicy || got.Drift() {
		t.Fatalf("ClassifyDenial(bare EPERM) = %q, want policy", got)
	}
	if got := ClassifyDenial(path, &os.PathError{Op: "open", Path: path, Err: unix.EACCES}); got != DenialAccess {
		t.Fatalf("ClassifyDenial(EACCES) = %q, want access", got)
	}
	if got := ClassifyDenial(path, errors.New("boom")); got != DenialOther {
		t.Fatalf("ClassifyDenial(other) = %q", got)
	}
}

func TestDarwinRootAliasesAndOSAncestors(t *testing.T) {
	for _, alias := range []string{"/etc", "/tmp", "/var"} {
		if !trustedRootAlias(alias) {
			t.Errorf("trustedRootAlias(%s) = false", alias)
		}
	}
	for _, path := range []string{"/private/etc", "/opt", "/Users", t.TempDir()} {
		if trustedRootAlias(path) {
			t.Errorf("trustedRootAlias(%s) = true", path)
		}
	}
	for _, path := range []string{"/", "/opt"} {
		if !AdvisoryAncestorPath(path) {
			t.Errorf("AdvisoryAncestorPath(%s) = false", path)
		}
	}
	if AdvisoryAncestorPath("/usr") || AdvisoryAncestorPath("/Users") {
		t.Error("an unrelated ancestor became advisory")
	}
}

func TestValidateTrustedFilePathCrossesEtcAlias(t *testing.T) {
	// /etc/hosts is root-owned, 0644 and reached through the /etc root alias.
	if err := ValidateTrustedFilePath("/etc/hosts", "fixture"); err != nil {
		t.Fatalf("ValidateTrustedFilePath(/etc/hosts) = %v; the /etc alias must be accepted", err)
	}
}

func TestValidateTrustedPathACLAcceptsAdminWrite(t *testing.T) {
	// Inheritance flags only exist on folders; on a file macOS drops them and
	// keeps the entry as an effective grant.
	path := t.TempDir()
	addDarwinACL(t, path, "admin allow add_file,delete_child")
	addDarwinACL(t, path, "everyone allow add_file,file_inherit,only_inherit")
	if err := validateTrustedPathACL(path); err != nil {
		t.Fatalf("admin and inherit-only entries were judged untrusted: %v", err)
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustChflags(t *testing.T, path, flags string) {
	t.Helper()
	if output, err := exec.Command("/usr/bin/chflags", flags, path).CombinedOutput(); err != nil {
		t.Fatalf("chflags %s: %v: %s", flags, err, output)
	}
}
