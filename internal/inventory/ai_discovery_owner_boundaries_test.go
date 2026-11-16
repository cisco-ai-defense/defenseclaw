// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// An excluded profile's sibling that only shares its name as a prefix is not
// inside it, so an ai_discovery.home_dirs folder there is still scanned
// (GAP-1258).
func TestExcludedHomeDoesNotCoverASiblingWithTheSamePrefix(t *testing.T) {
	root := t.TempDir()
	alice := discoveryHomeOwner{Home: filepath.Join(root, "alice"), UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"}
	owners := []discoveryHomeOwner{alice}
	for path, want := range map[string]bool{
		filepath.Join(root, "alice"):                 true,
		filepath.Join(root, "alice", "work"):         true,
		filepath.Join(root, "alice2"):                false,
		filepath.Join(root, "alice2", "work"):        false,
		filepath.Join(root, "alicework", "projects"): false,
	} {
		if got := insideDiscoveryHomeOf(owners, path); got != want {
			t.Errorf("insideDiscoveryHomeOf(%s) = %v, want %v", path, got, want)
		}
	}
	sibling := filepath.Join(root, "alice2", "work")
	opts := AIDiscoveryOptions{ExcludeUsers: []string{"alice"}, extraHomes: []string{sibling}}
	opts.applyPlatformHomeOwners(owners)
	if len(opts.HomeDirs) != 1 || opts.HomeDirs[0] != sibling {
		t.Fatalf("homes = %v, want the sibling folder %s kept", opts.HomeDirs, sibling)
	}
}

// With every profile excluded, an ai_discovery.home_dirs folder that is a
// link to an excluded profile, or sits below a link into one, is not
// scanned (GAP-1277); a plain folder elsewhere still is.
func TestAllExcludedProfilesKeepTheLinkRuleForExtraHomes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows; the junction case runs live")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bob := discoveryHomeOwner{Home: filepath.Join(root, "bob"), UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"}
	for _, dir := range []string{filepath.Join(bob.Home, "work"), filepath.Join(root, "plain")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	direct, parent := filepath.Join(root, "direct"), filepath.Join(root, "parent")
	if err := os.Symlink(bob.Home, direct); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bob.Home, parent); err != nil {
		t.Fatal(err)
	}
	below, plain := filepath.Join(parent, "work"), filepath.Join(root, "plain")
	opts := AIDiscoveryOptions{ExcludeUsers: []string{"bob"}, extraHomes: []string{direct, below, plain}}
	opts.applyPlatformHomeOwners([]discoveryHomeOwner{bob})
	svc := &ContinuousDiscoveryService{opts: opts}
	svc.dropLinkedExtraHomes()
	if homes := svc.opts.HomeDirs; len(homes) != 1 || homes[0] != plain || svc.opts.HomeDir != plain {
		t.Fatalf("homes = %v (HomeDir %q), want only %s", homes, svc.opts.HomeDir, plain)
	}
}

// One discovery scan asks the process-owner broker once, also when it is
// unavailable (GAP-1199).
func TestUnavailableProcessOwnerBrokerIsAskedOncePerScan(t *testing.T) {
	root := t.TempDir()
	alice := discoveryHomeOwner{Home: filepath.Join(root, "alice"), UserID: "S-1-5-21-1-2-3-1001", UserName: "alice", Domain: "HOST"}
	bob := discoveryHomeOwner{Home: filepath.Join(root, "bob"), UserID: "S-1-5-21-1-2-3-1002", UserName: "bob", Domain: "HOST"}
	opts := AIDiscoveryOptions{ExcludeUsers: []string{"bob"}}
	opts.applyPlatformHomeOwners([]discoveryHomeOwner{alice, bob})
	svc := &ContinuousDiscoveryService{opts: opts}
	calls := 0
	t.Cleanup(SetProcessAccountLookup(func() map[int]ProcessAccount {
		calls++
		return nil
	}))
	procs := []processInfo{
		{PID: 41, Comm: "codex.exe", Connector: "codex", Windows: true},
		{PID: 42, Comm: "claude.exe", Connector: "claudecode", Windows: true},
		{PID: 43, Comm: "codex.exe", Connector: "codex", Windows: true},
	}
	brokered := processAccountsOnce()
	svc.attributeProcessOwners(procs, brokered)
	procs = svc.withoutExcludedAccounts(procs, brokered)
	if calls != 1 || len(procs) != 3 {
		t.Fatalf("broker asked %d times, %d processes kept; want 1 and 3", calls, len(procs))
	}
}

// A brokered account name without a domain does not prove the process is an
// excluded domain account's, so an enrolled local account with the same
// short name keeps its process (GAP-1130).
func TestUnqualifiedBrokeredNameDoesNotDropAProcessAsExcluded(t *testing.T) {
	root := t.TempDir()
	local := discoveryHomeOwner{Home: filepath.Join(root, "local"), UserID: "S-1-5-21-1001", UserName: "alice", Domain: "HOST"}
	domain := discoveryHomeOwner{Home: filepath.Join(root, "domain"), UserID: "S-1-5-21-2001", UserName: "alice", Domain: "AD"}
	opts := AIDiscoveryOptions{ExcludeUsers: []string{`AD\alice`}}
	opts.applyPlatformHomeOwners([]discoveryHomeOwner{local, domain})
	svc := &ContinuousDiscoveryService{opts: opts}
	t.Cleanup(SetProcessAccountLookup(func() map[int]ProcessAccount {
		return map[int]ProcessAccount{
			42: {Name: "codex.exe", User: "alice"},
			43: {Name: "codex.exe", User: `AD\alice`},
		}
	}))
	procs := svc.withoutExcludedAccounts([]processInfo{
		{PID: 42, Comm: "codex.exe", Connector: "codex", Windows: true},
		{PID: 43, Comm: "codex.exe", Connector: "codex", Windows: true},
	}, processAccountsOnce())
	if len(procs) != 1 || procs[0].PID != 42 {
		t.Fatalf("processes = %+v, want only pid 42 (the qualified excluded account's pid 43 dropped)", procs)
	}
}
