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
	"strings"
	"testing"
)

// status and verify say how many enrolled accounts are in the
// root-equivalent docker group, and that the administrator policy is
// readable to them, without naming any account; enrolled accounts that never
// ran a sandbox count too, and no member means no advisory (GAP-0498).
func TestDockerGroupMembersAdvisory(t *testing.T) {
	h := newOSHost(t, "linux")
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, Home: "/home/bob"}
	carol := SandboxAccount{Name: "carol", UID: h.alice.UID + 2, Home: "/home/carol"}
	h.ops.accounts = append(h.ops.accounts, bob, carol)
	h.ops.groups["alice"] = []string{"alice", "docker"}
	h.ops.groups["bob"] = []string{"bob"}
	h.ops.groups["carol"] = []string{"carol", "docker"}
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5"})))
	h.registerSandboxUser(t, h.alice)
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		message := messagesOf(r.Warnings, codeDockerGroupMembers)
		if !strings.Contains(message, "2 of 3 enrolled accounts are in the docker group, which is root-equivalent") ||
			!strings.Contains(message, h.env.Layout.ConfigPath) || !strings.Contains(message, "only their own effective policy") ||
			!strings.Contains(message, "read and change what root can") || !strings.Contains(message, "the protected credentials and the services' environment") ||
			!strings.Contains(message, "do not protect them from a member") || !strings.Contains(message, "the only mitigation is to add only the accounts that run sandboxes") {
			t.Fatalf("%s: advisory = %q", action, message)
		}
		// References are not a mitigation against a member (GAP-0498 fix-up).
		if strings.Contains(message, "as a protected credential or environment reference") {
			t.Fatalf("%s: the advisory offers references as a mitigation: %q", action, message)
		}
		for _, name := range []string{"alice", "bob", "carol"} {
			if strings.Contains(message, name) {
				t.Errorf("%s: the advisory names %s: %q", action, name, message)
			}
		}
	}
	h.ops.groups["alice"] = []string{"alice"}
	h.ops.groups["carol"] = []string{"carol"}
	if r := h.run(Options{Action: ActionStatus}); hasWarning(r, codeDockerGroupMembers) {
		t.Fatalf("no member still warns: %+v", r.Warnings)
	}
}
