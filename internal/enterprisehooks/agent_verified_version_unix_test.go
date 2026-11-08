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
	versions := carryVerifiedAgentVersions(state, "alice", home, conns, nil, unreadableReason(path), nil)
	if versions["opencode"] != "" {
		t.Fatalf("carried %q with no record", versions["opencode"])
	}

	// A good read records the version and the file.
	versions = carryVerifiedAgentVersions(state, "alice", home, conns, map[string]string{"opencode": "2.2.3"}, nil, nil)
	if versions["opencode"] != "2.2.3" || state.VerifiedAgents["alice\x00opencode"].Version == "" && len(state.VerifiedAgents) == 0 {
		t.Fatalf("versions = %v, record = %+v", versions, state.VerifiedAgents)
	}

	// The same file, a failed read: the verified version stands in, up to the
	// bound, and the reason is dropped.
	for cycle := 1; cycle <= UnixVerifiedAgentCarryCycles; cycle++ {
		reasons := unreadableReason(path)
		got := carryVerifiedAgentVersions(state, "alice", home, conns, nil, reasons, nil)
		if got["opencode"] != "2.2.3" || reasons["opencode"] != "" {
			t.Fatalf("cycle %d: versions = %v, reasons = %v", cycle, got, reasons)
		}
	}
	reasons := unreadableReason(path)
	if got := carryVerifiedAgentVersions(state, "alice", home, conns, nil, reasons, nil); got["opencode"] != "" || reasons["opencode"] == "" {
		t.Fatalf("after %d failures in a row: versions = %v, reasons = %v; want unverified with the reason", UnixVerifiedAgentCarryCycles, got, reasons)
	}

	// A good read resets the count.
	carryVerifiedAgentVersions(state, "alice", home, conns, map[string]string{"opencode": "2.2.3"}, nil, nil)
	if got := carryVerifiedAgentVersions(state, "alice", home, conns, nil, unreadableReason(path), nil); got["opencode"] != "2.2.3" {
		t.Fatalf("after a good read: versions = %v", got)
	}

	// The file changed (same path, other content): not the verified binary.
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 1.0.0-replacement\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	reasons = unreadableReason(path)
	if got := carryVerifiedAgentVersions(state, "alice", home, conns, nil, reasons, nil); got["opencode"] != "" || reasons["opencode"] == "" {
		t.Fatalf("changed file: versions = %v, reasons = %v", got, reasons)
	}
	if len(state.VerifiedAgents) != 0 {
		t.Fatalf("changed file kept its record: %+v", state.VerifiedAgents)
	}

	// A copy discovery did not run (other accounts can change it) never
	// stands in, and not for another account's record.
	carryVerifiedAgentVersions(state, "alice", home, conns, map[string]string{"opencode": "2.2.3"}, nil, nil)
	noted := map[string]string{"opencode": UnixAgentUnversionedReasonPrefix + path + unixUntrustedCandidateNote}
	if got := carryVerifiedAgentVersions(state, "alice", home, conns, nil, noted, nil); got["opencode"] != "" {
		t.Fatalf("untrusted copy carried: %v", got)
	}
	carryVerifiedAgentVersions(state, "alice", home, conns, map[string]string{"opencode": "2.2.3"}, nil, nil)
	if got := carryVerifiedAgentVersions(state, "bob", home, conns, nil, unreadableReason(path), nil); got["opencode"] != "" {
		t.Fatalf("another account got alice's record: %v", got)
	}

	// The agent is gone: the record goes with it.
	if got := carryVerifiedAgentVersions(state, "alice", home, conns, nil, map[string]string{"opencode": "no opencode installation found for this user"}, nil); got["opencode"] != "" || len(state.VerifiedAgents) != 0 {
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
	carryVerifiedAgentVersions(state, "alice", home, []string{"opencode"}, map[string]string{"opencode": "2.2.3"}, nil, nil)
	if err := SaveUnixEnumeratorState(statePath, state); err != nil {
		t.Fatal(err)
	}
	loaded := LoadUnixEnumeratorState(statePath)
	if got := carryVerifiedAgentVersions(loaded, "alice", home, []string{"opencode"}, nil, unreadableReason(path), nil); got["opencode"] != "2.2.3" {
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
		opts.Discover = func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return copyStringMap(versions), copyStringMap(reasons), nil
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
