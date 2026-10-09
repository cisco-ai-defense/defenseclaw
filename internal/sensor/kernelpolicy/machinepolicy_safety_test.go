//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// An eligible account on vendor machine policy, with no targets.yaml row,
// anchors its installed command-line agent; an IDE surface named with it adds
// no row (security review, machine-policy enrollment).
func TestEligibleMachinePolicyAccountCanAnchorAnInstalledCLI(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F'}, 0o700); err != nil {
		t.Fatal(err)
	}
	accounts := []EligibleAccount{{User: "carol", UID: 1003, Home: home}}
	enrolled := Enrollment{}.WithMachinePolicy(accounts, []string{"claudecode", "antigravity"})
	if len(enrolled.Rows) != 1 || enrolled.Rows[0].Connector != "claudecode" || !enrolled.Rows[0].MachinePolicy {
		t.Fatalf("eligible-only CLI enrollment: %+v", enrolled.Rows)
	}
	installs := ResolveInstalls(OSFS(), enrolled, ResolveOptions{})
	roots := NewTracker().Update(OSFS(), []Proc{{
		PID: 4001, PPID: 1, StartTicks: 100, UID: 1003, EUID: 1003, Host: true,
		Exe: bin, Cmdline: []string{bin}, Comm: "claude",
	}}, installs, enrolled)
	if len(roots.Roots) != 1 || !roots.Roots[0].Native {
		t.Fatalf("machine-policy account's installed CLI did not anchor: %+v", roots.Roots)
	}
}

// A manifest row is the manifest's word on where an account lives: an
// eligible-accounts entry for the same uid under another home adds no row, so
// one uid never gets a second home whose binaries the manifest never named.
func TestMachinePolicyRowNeverGivesAManifestUIDASecondHome(t *testing.T) {
	e := mustEnrollment(t, `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: codex
`)
	got := e.WithMachinePolicy([]EligibleAccount{{User: "alice", UID: 1001, Home: "/srv/alice"}}, []string{"claudecode"})
	if len(got.Rows) != 1 || got.Rows[0].Connector != "codex" || got.Rows[0].Home != "/home/alice" {
		t.Fatalf("a second home became an anchor: %+v", got.Rows)
	}
}
