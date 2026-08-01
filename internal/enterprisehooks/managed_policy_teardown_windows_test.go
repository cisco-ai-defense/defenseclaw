// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

func TestValidateWindowsClaudeManagedPolicyTeardownStateExactIdentity(t *testing.T) {
	targets := []string{"S-1-5-21-111-222-333-1001"}
	opts := WindowsClaudeManagedPolicyTeardownOptions{
		HookExecutable:     `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		TargetSIDs:         targets,
	}
	state := windowsClaudeManagedPolicyState{
		SchemaVersion:      2,
		HookExecutable:     opts.HookExecutable,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		TargetSIDs:         append([]string(nil), targets...),
	}
	if err := validateWindowsClaudeManagedPolicyTeardownState(state, opts, targets); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*windowsClaudeManagedPolicyState)
	}{
		{"schema", func(value *windowsClaudeManagedPolicyState) { value.SchemaVersion = 1 }},
		{"binary", func(value *windowsClaudeManagedPolicyState) { value.HookExecutable += ".old" }},
		{"endpoint", func(value *windowsClaudeManagedPolicyState) { value.GatewayAddr = "127.0.0.1:18971" }},
		{"service", func(value *windowsClaudeManagedPolicyState) { value.GatewayServiceName = "OtherGateway" }},
		{"sid", func(value *windowsClaudeManagedPolicyState) { value.TargetSIDs[0] = "S-1-5-21-111-222-333-1009" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := state
			candidate.TargetSIDs = append([]string(nil), state.TargetSIDs...)
			test.mutate(&candidate)
			if err := validateWindowsClaudeManagedPolicyTeardownState(
				candidate,
				opts,
				targets,
			); err == nil {
				t.Fatal("tampered teardown identity was accepted")
			}
		})
	}
}
