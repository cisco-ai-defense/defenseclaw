// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"testing"
)

// A Codex-only deployment tears down an empty Claude target set, and this gate
// runs before the transaction opens.
func TestValidateWindowsClaudeManagedPolicyTeardownOptionsAcceptsNoTargets(t *testing.T) {
	original := windowsEnterpriseHookTrustCheck
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	t.Cleanup(func() { windowsEnterpriseHookTrustCheck = original })

	base := WindowsClaudeManagedPolicyTeardownOptions{
		HookExecutable:     `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
	}
	for name, empty := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			opts := base
			opts.TargetSIDs = empty
			targets, err := validateWindowsClaudeManagedPolicyTeardownOptions(opts)
			if err != nil {
				t.Fatalf("teardown with no Claude targets was rejected: %v", err)
			}
			if len(targets) != 0 {
				t.Fatalf("expected no Claude targets, got %v", targets)
			}
		})
	}

	t.Run("invalid sid still rejected", func(t *testing.T) {
		opts := base
		opts.TargetSIDs = []string{"not-a-sid"}
		if _, err := validateWindowsClaudeManagedPolicyTeardownOptions(opts); err == nil {
			t.Fatal("an unparseable target SID was accepted")
		}
	})

	// An empty set must not tear down a policy that exists.
	t.Run("enrolled policy still requires its targets", func(t *testing.T) {
		enrolled := windowsClaudeManagedPolicyState{
			SchemaVersion:      2,
			HookExecutable:     base.HookExecutable,
			GatewayAddr:        base.GatewayAddr,
			GatewayServiceName: base.GatewayServiceName,
			TargetSIDs:         []string{"S-1-5-21-111-222-333-1001"},
		}
		if err := validateWindowsClaudeManagedPolicyTeardownState(enrolled, base, nil); err == nil {
			t.Fatal("an enrolled Claude policy was accepted against an empty target set")
		}
	})
}

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

func TestValidateWindowsClaudeManagedPolicyLifecycleSnapshotExactPreimage(t *testing.T) {
	original := windowsEnterpriseHookTrustCheck
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	t.Cleanup(func() { windowsEnterpriseHookTrustCheck = original })

	opts := WindowsClaudeManagedPolicyTeardownOptions{
		HookExecutable:     `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		TargetSIDs:         []string{"S-1-5-21-111-222-333-1001"},
	}
	policy := []byte(`{"hooks":{"DefenseClaw":true}}`)
	state := windowsClaudeManagedPolicyState{
		SchemaVersion:      2,
		PolicySHA256:       windowsManagedPolicyDigest(policy),
		HookExecutable:     opts.HookExecutable,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		TargetSIDs:         append([]string(nil), opts.TargetSIDs...),
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := WindowsClaudeManagedPolicyTeardownSnapshot{
		PolicyExisted: true,
		Policy:        policy,
		StateExisted:  true,
		State:         stateBody,
	}
	if err := validateWindowsClaudeManagedPolicySnapshot(
		opts,
		opts.TargetSIDs,
		snapshot,
	); err != nil {
		t.Fatal(err)
	}

	tampered := snapshot
	tampered.Policy = append([]byte(nil), policy...)
	tampered.Policy[0] ^= 1
	if err := validateWindowsClaudeManagedPolicySnapshot(
		opts,
		opts.TargetSIDs,
		tampered,
	); err == nil {
		t.Fatal("lifecycle snapshot policy digest tamper was accepted")
	}

	emptyOpts := opts
	emptyOpts.TargetSIDs = nil
	if err := validateWindowsClaudeManagedPolicySnapshot(
		emptyOpts,
		nil,
		WindowsClaudeManagedPolicyTeardownSnapshot{},
	); err != nil {
		t.Fatalf("empty pre-activation snapshot was rejected: %v", err)
	}
	if err := validateWindowsClaudeManagedPolicySnapshot(
		opts,
		opts.TargetSIDs,
		WindowsClaudeManagedPolicyTeardownSnapshot{},
	); err == nil {
		t.Fatal("empty snapshot was accepted for a prior active enrollment")
	}
}

func TestWindowsClaudeManagedPolicyLifecycleSubsetRejectsForeignIdentity(t *testing.T) {
	allowed := []string{
		"S-1-5-21-111-222-333-1001",
		"S-1-5-21-111-222-333-1002",
	}
	if !windowsClaudeTargetSIDSubset(allowed[:1], allowed) {
		t.Fatal("manifest subset was rejected")
	}
	if windowsClaudeTargetSIDSubset(
		[]string{"S-1-5-21-111-222-333-1099"},
		allowed,
	) {
		t.Fatal("foreign target SID was accepted by lifecycle rollback")
	}
}
