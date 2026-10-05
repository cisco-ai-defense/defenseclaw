// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-1060: Amp installed root-owned in /opt/dc-agents was never enrolled,
// and status and verify said nothing while users ran it without hooks.
func TestUnixAgentOutsideDiscoveryFindsAnUnsearchedAdminPrefix(t *testing.T) {
	root := t.TempDir()
	oldRoots, oldPrefixes := unixAdminPrefixRoots, machinePrefixes
	t.Cleanup(func() { unixAdminPrefixRoots, machinePrefixes = oldRoots, oldPrefixes })
	unixAdminPrefixRoots = []string{root}
	machinePrefixes = func() []string { return []string{"/usr/local", "/usr"} }
	target := filepath.Join(root, "dc-agents", "lib", "node_modules", "@ampcode", "cli", "bin", "amp.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "dc-agents", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(bin, "amp")); err != nil {
		t.Fatal(err)
	}
	binary, prefix := UnixAgentOutsideDiscovery("amp")
	if binary != filepath.Join(bin, "amp") || prefix != filepath.Join(root, "dc-agents") {
		t.Fatalf("outside discovery = %q, %q", binary, prefix)
	}
	if binary, _ := UnixAgentOutsideDiscovery("codex"); binary != "" {
		t.Fatalf("codex is not installed there: %q", binary)
	}
	// Once agent_prefixes names the prefix, discovery searches it.
	machinePrefixes = func() []string { return []string{"/usr", filepath.Join(root, "dc-agents")} }
	if binary, _ := UnixAgentOutsideDiscovery("amp"); binary != "" {
		t.Fatalf("a searched prefix must not be reported: %q", binary)
	}
}

func TestEnumerateUnixReportsAnAgentInAnUnsearchedPrefix(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
		listed:   []string{"alice"},
	}
	opts := UnixEnumerateOptions{
		Resolver:  resolver,
		HomeRoots: []string{homes},
		UIDMin:    uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, map[string]string{"amp": "no amp installation found for this user"}, nil
		},
		OutsideDiscovery: func(conn string) (string, string) {
			if conn == "amp" {
				return "/opt/dc-agents/bin/amp", "/opt/dc-agents"
			}
			return "", ""
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("amp", "codex"), connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].Connector != "codex" {
		t.Fatalf("rows = %+v", manifest.Targets)
	}
	if len(report.Unprotected) != 1 {
		t.Fatalf("unprotected = %+v, want the amp install", report.Unprotected)
	}
	agent := report.Unprotected[0]
	message := agent.Message()
	if agent.Connector != "amp" || agent.User != "alice" || agent.Code != UnprotectedCodeAgentUnprotected ||
		!strings.Contains(message, "/opt/dc-agents/bin/amp") ||
		!strings.Contains(message, "add /opt/dc-agents to enterprise.enrollment.agent_prefixes") {
		t.Fatalf("unprotected agent = %+v (%s)", agent, message)
	}
}
