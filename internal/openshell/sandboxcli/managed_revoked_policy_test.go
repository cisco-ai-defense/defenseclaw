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

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A sandbox the organization's gateway stopped (its registration revoked)
// shows the policy it was created with (GAP-0079), but its status no longer
// reads as that permissive policy being in force: the Policy row says it is
// the created one, not in force, and that the sandbox can't start under it
// (GAP-0606). A running or stopped sandbox without a policy stop reads as
// before.
func TestRevokedSandboxStatusSaysTheCreatedPolicyIsNotInForce(t *testing.T) {
	ta := newTestApp(t, "")
	sb := &sandboxapi.Sandbox{Name: "dc-a", Harness: "claudecode", Phase: "stopped", Pack: "balanced", Profile: "balanced",
		NetworkMode: "allowlist", Approvals: "triage", WorkdirMode: "copy",
		StopReason: sandboxapi.ProfileStop("sandboxes", "claudecode", "it-security@example.com")}
	ta.printSandbox(sb)
	out := ta.output()
	has(t, out, "Policy", "pack balanced, network allowlist", "approvals triage: the policy it was created with, not in force",
		"can't start under it (see Stopped)", "Stopped")
	ta.fresh()
	sb.StopReason = ""
	ta.printSandbox(sb)
	if out := ta.output(); strings.Contains(out, "not in force") || !strings.Contains(out, "approvals triage") {
		t.Fatalf("a sandbox without a policy stop:\n%s", out)
	}
}
