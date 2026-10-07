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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

func TestEligibleMachinePolicyAccountCanAnchorAnInstalledCLI(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F'}, 0o700); err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) (int, string, error) { return 1003, home, nil }
	accounts := []enterprisehooks.UnixEligibleAccount{{User: "carol", UID: 1003, Home: home}}
	enrolled := mergeMachinePolicyEnrollment(kernelpolicy.Enrollment{}, accounts, []string{"claudecode", "antigravity"}, lookup)
	if len(enrolled.Rows) != 1 || enrolled.Rows[0].Connector != "claudecode" {
		t.Fatalf("eligible-only CLI enrollment: %+v", enrolled.Rows)
	}
	installs := kernelpolicy.ResolveInstalls(kernelpolicy.OSFS(), enrolled, kernelpolicy.ResolveOptions{})
	roots := kernelpolicy.NewTracker().Update(kernelpolicy.OSFS(), []kernelpolicy.Proc{{
		PID: 4001, PPID: 1, StartTicks: 100, UID: 1003, EUID: 1003, Host: true,
		Exe: bin, Cmdline: []string{bin}, Comm: "claude",
	}}, installs, enrolled)
	if len(roots.Roots) != 1 || !roots.Roots[0].Native {
		t.Fatalf("machine-policy account's installed CLI did not anchor: %+v", roots.Roots)
	}
}

func TestMachinePolicyEnrollmentRejectsStaleAccountIdentity(t *testing.T) {
	accounts := []enterprisehooks.UnixEligibleAccount{{User: "carol", UID: 1003, Home: "/home/carol"}}
	lookup := func(string) (int, string, error) { return 1004, "/home/carol", nil }
	if got := mergeMachinePolicyEnrollment(kernelpolicy.Enrollment{}, accounts, []string{"claudecode"}, lookup); len(got.Rows) != 0 {
		t.Fatalf("stale uid became an anchor: %+v", got.Rows)
	}
}
