// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The watcher retires machine admission and keeps the pinned vendor source in
// separate steps. In between, the pinned vendor hook still sends the calls of
// an excluded account, whether the authorizer admits it (exempt_users) or
// refuses it (no exemption, no ledger target, in either unenrolled_users
// mode), so the status must not say nothing inspects them.
func TestOwnStatusExcludedWatcherRetiresAdmissionBeforePinnedHook(t *testing.T) {
	for _, tc := range []struct {
		name   string
		exempt bool
		deny   bool
	}{
		{"exempt account", true, false},
		{"unexempt account, inspect", false, false},
		{"unexempt account, deny", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) { watcherRetiresAdmissionBeforePinnedHook(t, tc.exempt, tc.deny) })
	}
}

func watcherRetiresAdmissionBeforePinnedHook(t *testing.T, exempt, deny bool) {
	opts, _ := claudePolicyViewTestRoot(t, "linux")
	descriptorPath := filepath.Join(t.TempDir(), "runtime.json")
	descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{"claudecode"}}
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"carol"}
	if exempt {
		cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"}
	}
	if deny {
		cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny
	}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}}
	live := &Generation{N: 1, ConfigGen: 1, ConfigGenRecorded: true, Config: cfg}
	saved := loadStandaloneRuntimeDescriptor
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		copied := *descriptor
		return &copied, nil
	}
	t.Cleanup(func() { loadStandaloneRuntimeDescriptor = saved })
	authorizer := newManagedHookAuthorizer(cfg.Enterprise.Enrollment, nil,
		func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.SetGenerationSource(func() *Generation { return live })
	api.managedHookAuthz.Store(authorizer)
	watch := &managedPolicyViewWatch{api: api, authorizer: authorizer, goos: "linux", opts: opts, descriptorPath: descriptorPath}
	publishPolicyViewTestConnector(t, opts, "claudecode")
	pinPolicyView(t, opts, descriptor)
	if err := os.WriteFile(descriptorPath, []byte("version one"), 0o600); err != nil {
		t.Fatal(err)
	}
	watch.refresh()
	if !authorizer.machinePolicy.Load().connectors["claudecode"] || !api.managedPolicyView.Load().provenHook("claudecode", "carol") {
		t.Fatal("initial admission and pinned hook are required")
	}
	retired := *cfg
	retired.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{
		"claudecode": {Ownership: config.MachinePolicyOwnershipOff},
	}
	live = &Generation{N: 2, ConfigGen: 2, ConfigGenRecorded: true, Config: &retired}
	watch.refresh()
	view := api.managedPolicyView.Load()
	if authorizer.machinePolicy.Load().connectors["claudecode"] || view == nil || !view.provenHook("claudecode", "carol") || view.admitted["claudecode"] {
		t.Fatalf("watcher must have retired admission but kept the pinned source: machine=%v view=%+v", authorizer.machinePolicy.Load().connectors, view)
	}
	decision := authorizer.decide(managedHookPeer{UID: 5003, Name: "carol"}, "claudecode", "")
	if exempt && (!decision.Allow || !decision.Exempt) || !exempt && (decision.Allow || decision.Reason != managedHookReasonUIDUnregistered) {
		t.Fatalf("authorizer decision = %+v, want an exempt allow when exempt, else an unregistered refusal", decision)
	}
	rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
	requireExcludedReason(t, "claudecode", rows["claudecode"], inspectedCode, inspectedReason)
}
