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

package enterpriseunix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A sandbox change the lifecycle makes the same way for several accounts is
// one line that counts them and names none: apply and ensure documents go to
// management tooling (status-v2 GAP-0013). A change for one account names it.
func TestSandboxChangeForSeveralAccountsCountsThem(t *testing.T) {
	prerequisiteDocker := map[string]any{"install": "prerequisite", "driver": "docker"}
	vm := map[string]any{"install": "prerequisite", "driver": "vm"}
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, prerequisiteDocker)))
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, GID: h.alice.GID, Home: "/home/bob"}
	carol := SandboxAccount{Name: "carol", UID: h.alice.UID + 2, GID: h.alice.GID, Home: "/home/carol"}
	h.ops.accounts = append(h.ops.accounts, bob, carol)
	for _, a := range []SandboxAccount{h.alice, bob, carol} {
		if err := os.MkdirAll(h.env.P(filepath.Join(a.Home, h.env.daemonStateRel())), 0o700); err != nil {
			t.Fatal(err)
		}
		h.ops.status[a.UID] = SandboxStatus{Active: true}
	}
	r := h.ensure(sandboxConfig(t, "linux", true, vm))
	requireOK(t, r)
	changes := strings.Join(r.Changes, "\n")
	if !containsLine(r.Changes, "switched the sandbox setup of 3 accounts (driver docker -> vm)") {
		t.Errorf("no counted switch line: %v", r.Changes)
	}
	for _, name := range []string{"alice", "bob", "carol"} {
		if strings.Contains(changes, name) {
			t.Errorf("changes name %s: %v", name, r.Changes)
		}
	}

	// Sandboxes turned off for one account only: that line names it.
	h.ops.accounts = h.ops.accounts[:1]
	r = h.ensure(sandboxConfig(t, "linux", false, nil))
	requireOK(t, r)
	if !containsLine(r.Changes, fmt.Sprintf("stopped the sandbox daemon and OpenShell gateway of %s", h.alice.Name)) {
		t.Errorf("single-account line lost its name: %v", r.Changes)
	}
}
