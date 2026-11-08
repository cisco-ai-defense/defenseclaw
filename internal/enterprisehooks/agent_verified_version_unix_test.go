//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// installFakeOpenCode puts an executable named opencode in home/.local/bin and
// returns its path.
func installFakeOpenCode(t *testing.T, home, body string) string {
	t.Helper()
	dir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "opencode")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// testOwner is the account identity of the account that owns home in the
// carry tests that do not exercise the identity.
func testOwner(home string) UnixAgentOwner {
	return UnixAgentOwner{UID: 1001, Home: home, HomeInode: 7}
}

// ranFrom is the sources map of a discovery whose OpenCode answered from path.
func ranFrom(path string) map[string]string {
	return map[string]string{"opencode": path}
}

func unreadableReason(path string) map[string]string {
	return map[string]string{"opencode": UnixAgentUnversionedReasonPrefix + path}
}

// A version read that fails on an agent that has not changed keeps the version
// the last good read verified, for a few cycles; a changed file, a record
// that does not exist, a copy discovery did not run, or a run of failures
// longer than the bound all stay unverified.
func TestCarryVerifiedAgentVersionKeepsAnUnchangedAgentVerified(t *testing.T) {
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo 2.2.3")
	state := &UnixEnumeratorState{Version: 1}
	conns := []string{"opencode"}

	// No record yet: a failed read stays unverified (nothing is marked
	// protected that no read verified).
	versions := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, unreadableReason(path), nil, nil)
	if versions["opencode"] != "" {
		t.Fatalf("carried %q with no record", versions["opencode"])
	}

	// A good read records the version and the file.
	versions = carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, map[string]string{"opencode": "2.2.3"}, nil, ranFrom(path), nil)
	if versions["opencode"] != "2.2.3" || state.VerifiedAgents["alice\x00opencode"].Version == "" && len(state.VerifiedAgents) == 0 {
		t.Fatalf("versions = %v, record = %+v", versions, state.VerifiedAgents)
	}

	// The same file, a failed read: the verified version stands in, up to the
	// bound, and the reason is dropped.
	for cycle := 1; cycle <= UnixVerifiedAgentCarryCycles; cycle++ {
		reasons := unreadableReason(path)
		got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, reasons, nil, nil)
		if got["opencode"] != "2.2.3" || reasons["opencode"] != "" {
			t.Fatalf("cycle %d: versions = %v, reasons = %v", cycle, got, reasons)
		}
	}
	reasons := unreadableReason(path)
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, reasons, nil, nil); got["opencode"] != "" || reasons["opencode"] == "" {
		t.Fatalf("after %d failures in a row: versions = %v, reasons = %v; want unverified with the reason", UnixVerifiedAgentCarryCycles, got, reasons)
	}

	// A good read resets the count.
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, map[string]string{"opencode": "2.2.3"}, nil, ranFrom(path), nil)
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "2.2.3" {
		t.Fatalf("after a good read: versions = %v", got)
	}

	// The file changed (same path, other content): not the verified binary.
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 1.0.0-replacement\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	reasons = unreadableReason(path)
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, reasons, nil, nil); got["opencode"] != "" || reasons["opencode"] == "" {
		t.Fatalf("changed file: versions = %v, reasons = %v", got, reasons)
	}
	if len(state.VerifiedAgents) != 0 {
		t.Fatalf("changed file kept its record: %+v", state.VerifiedAgents)
	}

	// A copy discovery did not run (other accounts can change it) never
	// stands in, and not for another account's record.
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, map[string]string{"opencode": "2.2.3"}, nil, ranFrom(path), nil)
	noted := map[string]string{"opencode": UnixAgentUnversionedReasonPrefix + path + unixUntrustedCandidateNote}
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, noted, nil, nil); got["opencode"] != "" {
		t.Fatalf("untrusted copy carried: %v", got)
	}
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, map[string]string{"opencode": "2.2.3"}, nil, ranFrom(path), nil)
	if got := carryVerifiedAgentVersions(state, "bob", home, testOwner(home), conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "" {
		t.Fatalf("another account got alice's record: %v", got)
	}

	// The agent is gone: the record goes with it.
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, map[string]string{"opencode": "no opencode installation found for this user"}, nil, nil); got["opencode"] != "" || len(state.VerifiedAgents) != 0 {
		t.Fatalf("uninstalled: versions = %v, record = %+v", got, state.VerifiedAgents)
	}
}

// The verified record survives the state file, and a damaged record is
// dropped rather than trusted.
func TestUnixEnumeratorStateKeepsVerifiedAgentsAcrossRestarts(t *testing.T) {
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo 2.2.3")
	statePath := filepath.Join(t.TempDir(), "state.json")
	state := &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), []string{"opencode"}, map[string]string{"opencode": "2.2.3"}, nil, ranFrom(path), nil)
	if err := SaveUnixEnumeratorState(statePath, state); err != nil {
		t.Fatal(err)
	}
	loaded := LoadUnixEnumeratorState(statePath)
	if got := carryVerifiedAgentVersions(loaded, "alice", home, testOwner(home), []string{"opencode"}, nil, unreadableReason(path), nil, nil); got["opencode"] != "2.2.3" {
		t.Fatalf("after reload: versions = %v", got)
	}

	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(data), `"version": "2.2.3"`, `"version": "not a version"`, 1)
	if damaged == string(data) {
		t.Fatalf("state file has no version to damage: %s", data)
	}
	if err := os.WriteFile(statePath, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded = LoadUnixEnumeratorState(statePath); len(loaded.VerifiedAgents) != 0 {
		t.Fatalf("damaged record loaded: %+v", loaded.VerifiedAgents)
	}
}

// The failure the finding describes, through the enumerator: after a good
// cycle, one cycle whose probe could not read the running OpenCode does not
// publish hook_contract_unverified; OpenCode that really stops answering
// does, once the bound is spent; and a cycle with no record never hides it.
func TestEnumerateUnixMachinePolicyOpenCodeStaysVerifiedThroughAFailedRead(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	path := installFakeOpenCode(t, alice, "echo 2.2.3")
	cfg := enumeratorConfig("opencode")
	read := map[string]string{"opencode": "2.2.3"}
	opts := UnixEnumerateOptions{
		Resolver: &fakeResolver{
			accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
			listed:   []string{"alice"},
		},
		HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1, MachinePolicyConnectors: []string{"opencode"},
		State: &UnixEnumeratorState{Version: 1},
	}
	cycle := func(versions, reasons map[string]string) []UnprotectedAgent {
		t.Helper()
		opts.DiscoverSurfaces = func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
			found := UnixDiscovery{Versions: copyStringMap(versions), Reasons: copyStringMap(reasons)}
			if versions != nil {
				found.VersionSources = ranFrom(path)
			}
			return found, nil
		}
		_, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		return report.Unprotected
	}
	failed := unreadableReason(path)

	// First ever cycle fails to read: reported, as before.
	if got := cycle(nil, failed); len(got) != 1 || got[0].Code != UnprotectedCodeHookContractUnverified {
		t.Fatalf("no record: unprotected = %+v", got)
	}
	// Good read, then a failed one: nothing to report.
	if got := cycle(read, nil); len(got) != 0 {
		t.Fatalf("good read: unprotected = %+v", got)
	}
	for i := 0; i < UnixVerifiedAgentCarryCycles; i++ {
		if got := cycle(nil, failed); len(got) != 0 {
			t.Fatalf("failed read %d: unprotected = %+v", i+1, got)
		}
	}
	if got := cycle(nil, failed); len(got) != 1 || got[0].Code != UnprotectedCodeHookContractUnverified {
		t.Fatalf("failed reads past the bound: unprotected = %+v", got)
	}
	// A replaced binary is reported the first time its read fails.
	cycle(read, nil)
	time.Sleep(10 * time.Millisecond)
	installFakeOpenCode(t, alice, "echo replaced binary prints no version")
	if got := cycle(nil, failed); len(got) != 1 || got[0].Code != UnprotectedCodeHookContractUnverified {
		t.Fatalf("replaced binary: unprotected = %+v", got)
	}
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// a version a different CLI supplied is never carried for this one, a version
// from package metadata is bound to no file, and a version from the CLI itself
// is.
func TestCarryVerifiedAgentVersionBindsTheVersionToTheCLIThatSuppliedIt(t *testing.T) {
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo 2.2.3")
	other := filepath.Join(home, ".npm-global", "bin", "opencode")
	conns := []string{"opencode"}
	good := map[string]string{"opencode": "2.2.3"}

	// The version came from another copy: the record names that copy, so the
	// failed read of this one finds nothing to stand in for it.
	state := &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, ranFrom(other), nil)
	if len(state.VerifiedAgents) != 0 {
		t.Fatalf("a path that is not an installed CLI was recorded: %+v", state.VerifiedAgents)
	}
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "" {
		t.Fatalf("carried a version no run of this CLI supplied: %v", got)
	}

	// Package metadata or a stamp supplied it: no source, no record.
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, nil, nil)
	if len(state.VerifiedAgents) != 0 {
		t.Fatalf("a version with no source was recorded: %+v", state.VerifiedAgents)
	}

	// A later read without a source drops the record of an earlier one.
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, ranFrom(path), nil)
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, nil, nil)
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "" {
		t.Fatalf("carried a version whose latest source was metadata: %v", got)
	}

	// A source that is not a clean absolute path, or another connector CLI
	// name, is refused.
	for _, source := range []string{"opencode", home + "/.local/bin/../bin/opencode", filepath.Join(home, "bin", "other")} {
		carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, ranFrom(source), nil)
		if len(state.VerifiedAgents) != 0 {
			t.Fatalf("source %q recorded: %+v", source, state.VerifiedAgents)
		}
	}
}

// The version a later CLI printed does not keep a first CLI that never printed
// one verified: end to end through the real probe, with the later CLI gone the
// first one is reported as an unverified contract (GAP-0845 review 1).
// The twin: a CLI that answered and then fails once stays verified.
func TestEnumerateUnixVersionFromALaterCLIIsNotCarriedForAnEarlierCLI(t *testing.T) {
	oldPrefixes := machinePrefixes
	machinePrefixes = func() []string { return nil }
	t.Cleanup(func() { machinePrefixes = oldPrefixes })
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	home := makeHome(t, homes, "alice")
	first := filepath.Join(home, ".local", "bin", "opencode")
	later := filepath.Join(home, ".npm-global", "bin", "opencode")
	for path, body := range map[string]string{first: "exit 1", later: "echo opencode 2.2.3"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := unixAgentVersionRetryDelay
	unixAgentVersionRetryDelay = time.Millisecond
	t.Cleanup(func() { unixAgentVersionRetryDelay = old })
	opts := UnixEnumerateOptions{
		Resolver: &fakeResolver{
			accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}},
			listed:   []string{"alice"},
		},
		HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1, MachinePolicyConnectors: []string{"opencode"},
		State: &UnixEnumeratorState{Version: 1},
		DiscoverSurfaces: func(ctx context.Context, account unixidentity.Account, _ []string) (UnixDiscovery, error) {
			version, reason, source := DiscoverUnixAgentVersionFrom(ctx, account.Home, "opencode", true)
			found := UnixDiscovery{Versions: map[string]string{}, Reasons: map[string]string{}, VersionSources: map[string]string{}}
			if version != "" {
				found.Versions["opencode"], found.VersionSources["opencode"] = version, source
			} else {
				found.Reasons["opencode"] = reason
			}
			return found, nil
		},
	}
	cycle := func() []UnprotectedAgent {
		t.Helper()
		_, report, err := EnumerateUnix(context.Background(), enumeratorConfig("opencode"), connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		return report.Unprotected
	}
	if got := cycle(); len(got) != 0 {
		t.Fatalf("the later CLI answered, yet unprotected = %+v", got)
	}
	if err := os.Remove(later); err != nil {
		t.Fatal(err)
	}
	if got := cycle(); len(got) != 1 || got[0].Code != UnprotectedCodeHookContractUnverified {
		t.Fatalf("the first CLI never printed a version; unprotected = %+v, want one hook_contract_unverified row", got)
	}

	// Twin: the first CLI answers, then fails without having changed: its own
	// version stands in.
	marker := filepath.Join(home, "busy")
	script := "#!/bin/sh\nif [ -e " + marker + " ]; then exit 1; fi\necho opencode 2.2.3\n"
	if err := os.WriteFile(first, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := cycle(); len(got) != 0 {
		t.Fatalf("the first CLI answered, yet unprotected = %+v", got)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cycle(); len(got) != 0 {
		t.Fatalf("the first CLI answered before and did not change, yet unprotected = %+v", got)
	}
}

// DiscoverUnixAgentVersionFrom names the executable that ran, and nothing for
// a version read from package metadata.
func TestDiscoverUnixAgentVersionFromNamesTheExecutableThatAnswered(t *testing.T) {
	oldPrefixes := machinePrefixes
	machinePrefixes = func() []string { return nil }
	t.Cleanup(func() { machinePrefixes = oldPrefixes })
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo opencode 2.2.3")
	version, reason, source := DiscoverUnixAgentVersionFrom(context.Background(), home, "opencode", true)
	if version != "2.2.3" || reason != "" || source != path {
		t.Fatalf("version %q reason %q source %q, want 2.2.3 from %s", version, reason, source, path)
	}
	version, _, source = DiscoverUnixAgentVersionFrom(context.Background(), home, "opencode", false)
	if source != "" {
		t.Fatalf("a read that ran nothing named source %q (version %q)", source, version)
	}
}

// A verified version belongs to the account it was read for: the same user
// name with another uid, another home or a recreated home (another inode)
// does not inherit it, and the record is dropped, not just skipped.
func TestCarryVerifiedAgentVersionIsBoundToTheAccountIdentity(t *testing.T) {
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo 2.2.3")
	conns := []string{"opencode"}
	good := map[string]string{"opencode": "2.2.3"}
	owner := testOwner(home)
	otherHome := filepath.Join(filepath.Dir(home), "elsewhere")
	for name, changed := range map[string]UnixAgentOwner{
		"another uid":      {UID: owner.UID + 1, Home: owner.Home, HomeInode: owner.HomeInode},
		"another inode":    {UID: owner.UID, Home: owner.Home, HomeInode: owner.HomeInode + 1},
		"another home":     {UID: owner.UID, Home: otherHome, HomeInode: owner.HomeInode},
		"no inode anymore": {UID: owner.UID, Home: owner.Home},
	} {
		state := &UnixEnumeratorState{Version: 1}
		carryVerifiedAgentVersions(state, "alice", home, owner, conns, good, nil, ranFrom(path), nil)
		if got := carryVerifiedAgentVersions(state, "alice", home, changed, conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "" {
			t.Fatalf("%s: inherited the earlier account version: %v", name, got)
		}
		if len(state.VerifiedAgents) != 0 {
			t.Fatalf("%s: record of the earlier account kept: %+v", name, state.VerifiedAgents)
		}
		// The earlier identity coming back finds nothing to inherit either.
		if got := carryVerifiedAgentVersions(state, "alice", home, owner, conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "" {
			t.Fatalf("%s: record outlived the identity change: %v", name, got)
		}
	}
	// Twin: the same identity keeps the version.
	state := &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, owner, conns, good, nil, ranFrom(path), nil)
	if got := carryVerifiedAgentVersions(state, "alice", home, owner, conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "2.2.3" {
		t.Fatalf("same identity lost its version: %v", got)
	}
}

// A record written without an account identity (or with a damaged one) is not
// loaded from the state file.
func TestUnixEnumeratorStateDropsVerifiedAgentWithoutAnOwner(t *testing.T) {
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo 2.2.3")
	statePath := filepath.Join(t.TempDir(), "state.json")
	state := &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), []string{"opencode"}, map[string]string{"opencode": "2.2.3"}, nil, ranFrom(path), nil)
	record := state.VerifiedAgents["alice\x00opencode"]
	record.Owner = UnixAgentOwner{}
	state.VerifiedAgents["alice\x00opencode"] = record
	if err := SaveUnixEnumeratorState(statePath, state); err != nil {
		t.Fatal(err)
	}
	if loaded := LoadUnixEnumeratorState(statePath); len(loaded.VerifiedAgents) != 0 {
		t.Fatalf("record without an owner loaded: %+v", loaded.VerifiedAgents)
	}
}

// Through the enumerator: a user name that is reused by another uid, or whose
// home is recreated, is not enrolled on the version the earlier account read
// when its own read fails; the twin with an unchanged identity stays verified.
func TestEnumerateUnixReusedAccountDoesNotInheritAVerifiedVersion(t *testing.T) {
	for _, tc := range []struct {
		name       string
		uidDelta   int
		inodeAfter uint64
		wantRow    bool
	}{
		{name: "same account", inodeAfter: 7},
		{name: "reused user name, new uid", uidDelta: 1, inodeAfter: 7, wantRow: true},
		{name: "recreated home", inodeAfter: 8, wantRow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedTestDir(t)
			homes := filepath.Join(root, "home")
			if err := os.MkdirAll(homes, 0o755); err != nil {
				t.Fatal(err)
			}
			uid, gid := os.Getuid(), os.Getgid()
			home := makeHome(t, homes, "alice")
			path := installFakeOpenCode(t, home, "echo opencode 2.2.3")
			resolver := &fakeResolver{
				accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}},
				listed:   []string{"alice"},
			}
			inode := uint64(7)
			readFails := false
			opts := UnixEnumerateOptions{
				Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 2,
				MachinePolicyConnectors: []string{"opencode"}, State: &UnixEnumeratorState{Version: 1},
				CheckHome: func(string, int) HomeCheck { return HomeCheck{State: HomeAvailable, Inode: inode} },
				DiscoverSurfaces: func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
					if readFails {
						return UnixDiscovery{Reasons: unreadableReason(path)}, nil
					}
					return UnixDiscovery{Versions: map[string]string{"opencode": "2.2.3"}, VersionSources: ranFrom(path)}, nil
				},
			}
			cfg := enumeratorConfig("opencode")
			cfg.Enterprise.Enrollment.UnenrolledUsers = "deny"
			if _, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts); err != nil || len(report.Unprotected) != 0 {
				t.Fatalf("first account: err = %v, unprotected = %+v", err, report.Unprotected)
			}
			account := resolver.accounts["alice"]
			account.UID += tc.uidDelta
			account.GID += tc.uidDelta
			resolver.accounts["alice"] = account
			inode, readFails = tc.inodeAfter, true
			manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
			if err != nil {
				t.Fatal(err)
			}
			unverified := 0
			for _, item := range report.Unprotected {
				if item.Code == UnprotectedCodeHookContractUnverified {
					unverified++
				}
			}
			if tc.wantRow && unverified != 1 {
				t.Fatalf("the new identity inherited the earlier version: unprotected = %+v, targets = %+v", report.Unprotected, manifest.Targets)
			}
			if !tc.wantRow && len(report.Unprotected) != 0 {
				t.Fatalf("the unchanged account lost its verified version: unprotected = %+v", report.Unprotected)
			}
		})
	}
}

// An unknown home inode (zero) proves nothing: two unknowns are not the same
// home. Nothing is recorded for such an owner, a stored record without an
// inode is not loaded, and an earlier record is not carried for it.
func TestCarryVerifiedAgentVersionNeverMatchesAnUnknownHomeInode(t *testing.T) {
	home := t.TempDir()
	path := installFakeOpenCode(t, home, "echo 2.2.3")
	conns := []string{"opencode"}
	good := map[string]string{"opencode": "2.2.3"}
	unknown := UnixAgentOwner{UID: 1001, Home: home}

	state := &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, unknown, conns, good, nil, ranFrom(path), nil)
	if len(state.VerifiedAgents) != 0 {
		t.Fatalf("a read for an owner without an inode was recorded: %+v", state.VerifiedAgents)
	}
	if got := carryVerifiedAgentVersions(state, "alice", home, unknown, conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "" {
		t.Fatalf("two unknown inodes carried a version: %v", got)
	}

	// A record that predates the rule (or was edited) is not loaded.
	statePath := filepath.Join(t.TempDir(), "state.json")
	state = &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, ranFrom(path), nil)
	record := state.VerifiedAgents["alice\x00opencode"]
	record.Owner.HomeInode = 0
	state.VerifiedAgents["alice\x00opencode"] = record
	if err := SaveUnixEnumeratorState(statePath, state); err != nil {
		t.Fatal(err)
	}
	if loaded := LoadUnixEnumeratorState(statePath); len(loaded.VerifiedAgents) != 0 {
		t.Fatalf("record without a home inode loaded: %+v", loaded.VerifiedAgents)
	}

	// Twin: a known inode still carries.
	state = &UnixEnumeratorState{Version: 1}
	carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, good, nil, ranFrom(path), nil)
	if got := carryVerifiedAgentVersions(state, "alice", home, testOwner(home), conns, nil, unreadableReason(path), nil, nil); got["opencode"] != "2.2.3" {
		t.Fatalf("a known identity lost its version: %v", got)
	}
}

// Through the enumerator on a filesystem that cannot supply a home inode: a
// home replaced by a new directory (the CLI moved into it) is not enrolled on
// the version read in the old home when its own read fails.
func TestEnumerateUnixUnknownHomeInodeDoesNotInheritAVerifiedVersion(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	home := makeHome(t, homes, "alice")
	path := installFakeOpenCode(t, home, "echo opencode 2.2.3")
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}},
		listed:   []string{"alice"},
	}
	readFails := false
	opts := UnixEnumerateOptions{
		Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		MachinePolicyConnectors: []string{"opencode"}, State: &UnixEnumeratorState{Version: 1},
		CheckHome: func(string, int) HomeCheck { return HomeCheck{State: HomeAvailable} },
		DiscoverSurfaces: func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
			if readFails {
				return UnixDiscovery{Reasons: unreadableReason(path)}, nil
			}
			return UnixDiscovery{Versions: map[string]string{"opencode": "2.2.3"}, VersionSources: ranFrom(path)}, nil
		},
	}
	cfg := enumeratorConfig("opencode")
	cfg.Enterprise.Enrollment.UnenrolledUsers = "deny"
	if _, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts); err != nil || len(report.Unprotected) != 0 {
		t.Fatalf("first read: err = %v, unprotected = %+v", err, report.Unprotected)
	}
	old := home + ".old"
	if err := os.Rename(home, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(old, ".local"), filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	readFails = true
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range report.Unprotected {
		if item.Code == UnprotectedCodeHookContractUnverified {
			return
		}
	}
	t.Fatalf("an unknown home inode let a replaced home inherit the earlier version: unprotected = %+v, targets = %+v", report.Unprotected, manifest.Targets)
}
