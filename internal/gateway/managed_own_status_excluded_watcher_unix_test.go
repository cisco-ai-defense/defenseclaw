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
// separate steps. In between, an exempt excluded account is still admitted by
// the hook authorizer and a pinned hook still sends its calls, so the status
// must not say nothing inspects them.
func TestOwnStatusExcludedWatcherRetiresAdmissionBeforePinnedHook(t *testing.T) {
	opts, _ := claudePolicyViewTestRoot(t, "linux")
	descriptorPath := filepath.Join(t.TempDir(), "runtime.json")
	descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{"claudecode"}}
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"carol"}
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"}
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
	if decision := authorizer.decide(managedHookPeer{UID: 5003, Name: "carol"}, "claudecode", ""); !decision.Allow || !decision.Exempt {
		t.Fatalf("authorizer decision = %+v, want an exempt allow", decision)
	}
	rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
	requireExcludedReason(t, "claudecode", rows["claudecode"], "excluded_users_inspected", exemptReason)
}
