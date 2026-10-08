//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// A known row used to take any version its user's install reported,
// including one without a verified hook contract. The guardian then passed
// that version to Install, which refuses it, so no repair ran again and the
// user could delete DefenseClaw's hooks for good. The row now keeps its last
// verified version, and the unverified one is reported.
func TestEnumerateUnixKnownRowKeepsItsVerifiedVersionForAnUnverifiedOne(t *testing.T) {
	const verified, unverified, upgraded = "0.142.0", "0.100.0", "0.150.0"
	if connector.ResolveHookContract("codex", verified).Status != connector.HookCompatibilityKnown ||
		connector.ResolveHookContract("codex", upgraded).Status != connector.HookCompatibilityKnown ||
		connector.ResolveHookContract("codex", unverified).Status == connector.HookCompatibilityKnown {
		t.Fatal("fixture versions no longer match the contract table")
	}
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	info, err := os.Stat(alice)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	writePrevious := func(version string) {
		t.Helper()
		data, err := MarshalUnixTargetsManifest(Manifest{Version: 1, Targets: []ManifestTarget{{
			User: "alice", UserHome: alice, UID: intPointer(uid), GID: intPointer(gid), Connector: "codex",
			DataDir: filepath.Join(alice, ".defenseclaw"), AgentVersion: version, Enabled: &enabled, HomeInode: statInode(t, info),
		}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
		listed:   []string{"alice"},
	}
	discovered := ""
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": discovered}, nil, nil
		},
	}
	enumerate := func(previous, installed string) (string, []UnprotectedAgent) {
		t.Helper()
		writePrevious(previous)
		discovered = installed
		opts.State = &UnixEnumeratorState{Version: 1}
		manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(manifest.Targets) != 1 {
			t.Fatalf("rows = %+v, want alice's codex row", manifest.Targets)
		}
		return manifest.Targets[0].AgentVersion, report.Unprotected
	}

	version, unprotected := enumerate(verified, unverified)
	if version != verified {
		t.Fatalf("row version = %s, want it kept at %s", version, verified)
	}
	if len(unprotected) != 1 || unprotected[0].Code != UnprotectedCodeHookContractUnverified || unprotected[0].Version != unverified ||
		unprotected[0].User != "alice" || !strings.Contains(unprotected[0].Reason, "the row stays enrolled at "+verified) {
		t.Fatalf("unprotected = %+v, want the unverified version reported", unprotected)
	}
	if version, unprotected := enumerate(verified, upgraded); version != upgraded || len(unprotected) != 0 {
		t.Fatalf("a verified upgrade: row %s, unprotected %+v; want it followed", version, unprotected)
	}
	// With no verified version to keep, the row records what is installed.
	if version, unprotected := enumerate(unverified, "0.101.0"); version != "0.101.0" || len(unprotected) != 0 {
		t.Fatalf("from an unverified version: row %s, unprotected %+v", version, unprotected)
	}
}

// A never-enrolled user whose home is group- or other-writable used to be
// skipped before discovery: no rows, no report, nothing in status. A
// standard user could chmod g+w their home and run agents unseen. They are
// now reported, from a discovery that executes nothing in that home.
func TestEnumerateUnixReportsAgentsInAnUntrustedHomeWithoutRunningThem(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	bob := makeHome(t, homes, "bob")
	if err := os.Chmod(bob, 0o775); err != nil {
		t.Fatal(err)
	}
	if check := CheckUnixTargetHome(bob, uid); check.State != HomeUntrusted || !check.LooseMode {
		t.Fatalf("fixture home check = %+v, want an untrusted, loose-mode home", check)
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{"bob": {Name: "bob", UID: uid, GID: gid, Home: bob, Shell: "/bin/bash"}},
		listed:   []string{"bob"},
	}
	staticCalls := 0
	opts := UnixEnumerateOptions{
		Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			t.Error("the executing discovery must never run in an untrusted home")
			return nil, nil, nil
		},
		DiscoverStatic: func(_ context.Context, account unixidentity.Account, connectors []string) (map[string]string, map[string]string, error) {
			staticCalls++
			sorted := append([]string(nil), connectors...)
			sort.Strings(sorted)
			if account.Name != "bob" || strings.Join(sorted, ",") != "amp,codex,opencode" {
				t.Errorf("static discovery for %s %v", account.Name, connectors)
			}
			return map[string]string{"codex": "0.150.0"}, map[string]string{
				"opencode": UnixAgentUnversionedReasonPrefix + filepath.Join(bob, ".local", "bin", "opencode"),
				"amp":      "no amp installation found for this user",
			}, nil
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("codex", "opencode", "amp"), connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 0 || len(report.EligibleAccounts) != 0 || staticCalls != 1 {
		t.Fatalf("rows %+v eligible %+v static calls %d; want no enrollment and one static discovery", manifest.Targets, report.EligibleAccounts, staticCalls)
	}
	byConnector := map[string]UnprotectedAgent{}
	for _, agent := range report.Unprotected {
		byConnector[agent.Connector] = agent
	}
	if len(report.Unprotected) != 2 || byConnector["codex"].Version != "0.150.0" || byConnector["opencode"].User != "bob" {
		t.Fatalf("unprotected = %+v, want bob's codex and opencode", report.Unprotected)
	}
	for _, agent := range report.Unprotected {
		if agent.Code != UnprotectedCodeAgentUnprotected || !strings.Contains(agent.Reason, "group/other writable") ||
			!strings.Contains(agent.Reason, "does not enroll agents in an untrusted home") || !strings.Contains(agent.Reason, "remove group and other write") {
			t.Fatalf("entry %+v must explain the untrusted home and the fix", agent)
		}
	}
	// The home's mode must not cost bob his identity record, and so the
	// profile assigned to him (GAP-0714); without an agent the account
	// itself is reported, so status and verify name it (GAP-0646).
	if len(report.IdentityAccounts) != 1 || report.IdentityAccounts[0].UID != uid {
		t.Fatalf("identity accounts = %+v, want bob", report.IdentityAccounts)
	}
	opts.DiscoverStatic = func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
		return nil, nil, nil
	}
	if _, report, err = EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), opts); err != nil ||
		len(report.Unprotected) != 1 || report.Unprotected[0].Code != UnprotectedCodeHomeUntrusted ||
		!strings.Contains(report.Unprotected[0].Message(), "user bob is not enrolled: user home") {
		t.Fatalf("no agents: err %v unprotected %+v, want bob's untrusted home reported", err, report.Unprotected)
	}
}

// Static discovery reads package metadata and checks that the CLI exists;
// it never runs the CLI, which another user may have planted.
func TestDiscoverUnixAgentVersionStaticallyExecutesNothing(t *testing.T) {
	withoutMachinePrefixes(t)
	home := trustedTestDir(t)
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "ran")
	script := "#!/bin/sh\ntouch '" + marker + "'\necho 1.2.3\n"
	if err := os.WriteFile(filepath.Join(bin, "opencode"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	version, reason := DiscoverUnixAgentVersionStatically(context.Background(), home, "opencode")
	if version != "" || !UnixAgentInstalledWithoutVersion(reason) || !strings.HasSuffix(reason, filepath.Join(bin, "opencode")) {
		t.Fatalf("opencode = %q (%s), want it found installed, without a version", version, reason)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("static discovery executed the CLI: %v", err)
	}
	pkg := filepath.Join(home, ".npm-global", "lib", "node_modules", "@openai", "codex")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"@openai/codex","version":"0.151.2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if version, _ := DiscoverUnixAgentVersionStatically(context.Background(), home, "codex"); version != "0.151.2" {
		t.Fatalf("codex from package metadata = %q", version)
	}
	if _, reason := DiscoverUnixAgentVersionStatically(context.Background(), home, "amp"); UnixAgentInstalledWithoutVersion(reason) {
		t.Fatalf("an absent agent reported installed: %s", reason)
	}
}
