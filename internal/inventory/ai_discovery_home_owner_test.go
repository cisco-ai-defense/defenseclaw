// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A service-context scan (managed Windows) attributes what it finds in a
// profile, and the agent processes started from one, to that profile's
// account, and finds agents whose folders a per-user variable names
// ($LOCALAPPDATA/hermes) in every profile rather than the service's own.
func TestServiceContextScanAttributesSignalsToProfileOwner(t *testing.T) {
	root := t.TempDir()
	alice := filepath.Join(root, "Users", "alice")
	bob := filepath.Join(root, "Users", "bob")
	for _, dir := range []string{
		filepath.Join(alice, "AppData", "Local", "hermes", "skills"),
		filepath.Join(bob, "AppData", "Local", "hermes", "skills"),
		filepath.Join(bob, ".kiro", "settings"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bob, ".kiro", "settings", "cli.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	owners := []discoveryHomeOwner{
		{Home: alice, UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"},
		{Home: bob, UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"},
	}
	s := &ContinuousDiscoveryService{
		opts: AIDiscoveryOptions{HomeDir: alice, HomeDirs: []string{alice, bob}, homeOwners: owners},
		catalog: []AISignature{
			{ID: "hermes", Name: "Hermes", SupportedConnector: "hermes", ConfigPaths: []string{"$LOCALAPPDATA/hermes/skills"}},
			{ID: "kiro", Name: "Kiro", SupportedConnector: "kiro", ConfigPaths: []string{"~/.kiro/settings/cli.json"}},
		},
	}

	got := map[string]string{}
	for _, sig := range s.detectConfigPaths() {
		got[sig.SignatureID+"/"+sig.UserName] = sig.UserID
	}
	want := map[string]string{
		"hermes/alice": "S-1-5-21-1-2-3-1001",
		"hermes/bob":   "S-1-5-21-1-2-3-1002",
		"kiro/bob":     "S-1-5-21-1-2-3-1002",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("config signals by signature/user = %v, want %v", got, want)
	}

	procs := []processInfo{
		{PID: 10, PPID: 1, Comm: "codex.exe", Image: strings.ToUpper(filepath.Join(alice, ".codex", "bin", "codex.exe")), Windows: true},
		{PID: 11, PPID: 10, Comm: "node.exe", Image: filepath.Join(root, "Program Files", "nodejs", "node.exe"), Windows: true},
		{PID: 20, PPID: 1, Comm: "claude.exe", Image: filepath.Join(bob, ".local", "bin", "claude.exe"), Windows: true},
		{PID: 30, PPID: 1, Comm: "pwsh.exe", Image: filepath.Join(root, "Program Files", "PowerShell", "pwsh.exe"), Windows: true},
	}
	s.attributeProcessOwners(procs)
	for i, wantOwner := range []string{"alice", "alice", "bob", ""} {
		if procs[i].OwnerName != wantOwner {
			t.Fatalf("process %s owner = %q, want %q", procs[i].Comm, procs[i].OwnerName, wantOwner)
		}
	}
	signal := s.signalFromProcess(AISignature{ID: "claude-code"}, procs[2], procs[2].StartedAt, MatchKindExact, 1)
	if signal.UserID != "S-1-5-21-1-2-3-1002" || signal.UserName != "bob" || signal.Runtime.User != "bob" {
		t.Fatalf("process signal user = %q/%q runtime %q", signal.UserID, signal.UserName, signal.Runtime.User)
	}

	denied := &fs.PathError{Op: "open", Path: alice, Err: fs.ErrPermission}
	if !s.discoveryAccessSkipped(denied) {
		t.Fatal("a profile folder the service was not granted failed the scan")
	}
	if (&ContinuousDiscoveryService{}).discoveryAccessSkipped(denied) {
		t.Fatal("a per-user scan skipped a permission error")
	}
}

// Without platform profile owners (every per-user and Unix install) nothing
// is attributed and per-user variables expand as before.
func TestPerUserScanLeavesSignalsUnattributed(t *testing.T) {
	home := t.TempDir()
	s := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}}}
	if _, ok := s.profileRelativeCandidate("$LOCALAPPDATA/hermes/config.yaml"); ok {
		t.Fatal("per-user variable rewritten outside a service-context scan")
	}
	sig := s.signalFromPath(AISignature{ID: "x"}, SignalSupportedConnector, "config", filepath.Join(home, ".x"))
	if sig.UserID != "" || sig.UserName != "" {
		t.Fatalf("per-user scan signal attributed to %q/%q", sig.UserID, sig.UserName)
	}
}
