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
		// Kiro CLI's install folder (GAP-1210): what the service can still
		// see when the guardian protects the user's .kiro.
		filepath.Join(alice, "AppData", "Local", "Kiro-Cli"),
		// Copilot CLI's package cache and Devin CLI's install (GAP-1739):
		// what the service sees when the guardian protects .copilot and
		// AppData\Roaming\devin.
		filepath.Join(alice, "AppData", "Local", "copilot", "pkg"),
		filepath.Join(bob, "AppData", "Local", "copilot", "pkg"),
		filepath.Join(alice, "AppData", "Local", "devin", "cli"),
		filepath.Join(bob, "AppData", "Local", "devin", "cli"),
		// Amp's npm install and cursor-agent's install (GAP-1963,
		// GAP-1739): what the service sees when the guardian protects
		// .config, and for a user without ~\.cursor\mcp.json.
		filepath.Join(alice, "AppData", "Roaming", "npm", "node_modules", "@ampcode", "cli"),
		filepath.Join(bob, "AppData", "Local", "cursor-agent"),
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
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	configPaths := map[string]string{}
	for _, sig := range catalog {
		configPaths[sig.ID] = strings.Join(sig.ConfigPaths, "\n")
	}
	for id, want := range map[string]string{"kiro": "$LOCALAPPDATA/Kiro-Cli", "copilot": "$LOCALAPPDATA/copilot/pkg", "devin": "$LOCALAPPDATA/devin/cli",
		"amp": "$APPDATA/npm/node_modules/@ampcode/cli", "cursor": "$LOCALAPPDATA/cursor-agent"} {
		if !strings.Contains(configPaths[id], want) {
			t.Fatalf("catalog %s config paths %q do not name its install folder %s", id, configPaths[id], want)
		}
	}
	s := &ContinuousDiscoveryService{
		opts: AIDiscoveryOptions{HomeDir: alice, HomeDirs: []string{alice, bob}, homeOwners: owners},
		catalog: []AISignature{
			{ID: "hermes", Name: "Hermes", SupportedConnector: "hermes", ConfigPaths: []string{"$LOCALAPPDATA/hermes/skills"}},
			{ID: "kiro", Name: "Kiro", SupportedConnector: "kiro", ConfigPaths: []string{"~/.kiro/settings/cli.json", "$LOCALAPPDATA/Kiro-Cli"}},
			{ID: "copilot", Name: "GitHub Copilot", SupportedConnector: "copilot", ConfigPaths: []string{"~/.copilot/config.json", "$LOCALAPPDATA/copilot/pkg"}},
			{ID: "devin", Name: "Devin", SupportedConnector: "devin", ConfigPaths: []string{"$APPDATA/devin/config.json", "$LOCALAPPDATA/devin/cli"}},
			{ID: "amp", Name: "Amp", SupportedConnector: "amp", ConfigPaths: []string{"~/.config/amp/settings.json", "$APPDATA/npm/node_modules/@ampcode/cli"}},
			{ID: "cursor", Name: "Cursor", SupportedConnector: "cursor", ConfigPaths: []string{"~/.cursor/mcp.json", "$LOCALAPPDATA/cursor-agent"}},
		},
	}

	got := map[string]string{}
	for _, sig := range s.detectConfigPaths() {
		got[sig.SignatureID+"/"+sig.UserName] = sig.UserID
	}
	want := map[string]string{
		"hermes/alice":  "S-1-5-21-1-2-3-1001",
		"hermes/bob":    "S-1-5-21-1-2-3-1002",
		"kiro/alice":    "S-1-5-21-1-2-3-1001",
		"kiro/bob":      "S-1-5-21-1-2-3-1002",
		"copilot/alice": "S-1-5-21-1-2-3-1001",
		"copilot/bob":   "S-1-5-21-1-2-3-1002",
		"devin/alice":   "S-1-5-21-1-2-3-1001",
		"devin/bob":     "S-1-5-21-1-2-3-1002",
		"amp/alice":     "S-1-5-21-1-2-3-1001",
		"cursor/bob":    "S-1-5-21-1-2-3-1002",
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
