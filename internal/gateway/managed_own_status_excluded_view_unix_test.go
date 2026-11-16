//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The policy view is the proof that the vendor hook is there; the authorizer
// is what decides the calls. An excluded account status reads both: it never
// says "nothing inspects" while the authorizer still admits the connector, and
// never promises inspection from a hook it cannot prove.

// A descriptor-only removal leaves the authorizer with its admitted connector
// while the watcher publishes no view.
func TestOwnStatusExcludedAfterDescriptorOnlyRemovalClaimsNeitherNothingNorInspection(t *testing.T) {
	for _, deny := range []bool{false, true} {
		name := "inspect"
		if deny {
			name = "deny"
		}
		t.Run(name, func(t *testing.T) {
			opts, _ := claudePolicyViewTestRoot(t, "linux")
			descriptorPath := filepath.Join(t.TempDir(), "runtime.json")
			descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{"claudecode"}}
			cfg := &config.Config{DeploymentMode: "managed_enterprise"}
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Enterprise.Enrollment.ExcludeUsers = []string{"carol"}
			if deny {
				cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny
			}
			cfg.Guardrail.Enabled = true
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}}
			live := &Generation{N: 1, ConfigGen: 1, ConfigGenRecorded: true, Config: cfg}
			saved := loadStandaloneRuntimeDescriptor
			loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) { copy := *descriptor; return &copy, nil }
			t.Cleanup(func() { loadStandaloneRuntimeDescriptor = saved })
			authorizer := newManagedHookAuthorizer(cfg.Enterprise.Enrollment, nil, func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
			api.SetGenerationSource(func() *Generation { return live })
			api.managedHookAuthz.Store(authorizer)
			watch := &managedPolicyViewWatch{api: api, authorizer: authorizer, goos: "linux", opts: opts, descriptorPath: descriptorPath}
			publishPolicyViewTestConnector(t, opts, enterprisepolicy.ConnectorClaudeCode)
			pinPolicyView(t, opts, descriptor)
			if err := os.WriteFile(descriptorPath, []byte("v1"), 0o600); err != nil {
				t.Fatal(err)
			}
			watch.refresh()
			if api.managedPolicyView.Load() == nil {
				t.Fatal("initial policy view was not published")
			}
			// Benign twin: with the proven view the inspect case says inspected.
			if !deny {
				requireExcludedReason(t, "claudecode with the view", ownStatusRowFor(t, api, "uid", "5003", "carol", "claudecode"),
					inspectedCode, inspectedReason)
			}
			descriptor.MachinePolicyConnectors = nil
			if err := os.WriteFile(descriptorPath, []byte("version two"), 0o600); err != nil {
				t.Fatal(err)
			}
			watch.refresh()
			if api.managedPolicyView.Load() != nil {
				t.Fatal("the view must be nil after a descriptor-only removal")
			}
			requireExcludedReason(t, "claudecode", ownStatusRowFor(t, api, "uid", "5003", "carol", "claudecode"), unknownCode, unknownReason)
		})
	}
}

// A published vendor hook that was removed after it was pinned leaves the
// source unproven: the status does not promise inspection, and with the hook
// in place it still says inspected.
func TestOwnStatusExcludedWithTheVendorHookRemovedDoesNotPromiseInspection(t *testing.T) {
	for _, removed := range []bool{false, true} {
		name := "hook in place"
		wantCode, wantText := inspectedCode, inspectedReason
		if removed {
			name = "hook removed"
			wantCode, wantText = unknownCode, unknownReason
		}
		t.Run(name, func(t *testing.T) {
			opts, dir := claudePolicyViewTestRoot(t, "linux")
			descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{"claudecode"}}
			publishPolicyViewTestConnector(t, opts, "claudecode")
			pinPolicyView(t, opts, descriptor)
			if removed {
				if err := os.Remove(filepath.Join(dir, "managed-settings.d", enterprisepolicy.DefenseClawDropInName)); err != nil {
					t.Fatal(err)
				}
			}
			view := computeManagedPolicyView(opts, descriptor)
			view.admitted = map[string]bool{"claudecode": true}
			api := ownStatusExcludedFixture(t, []string{"carol"}, nil)
			api.managedPolicyView.Store(view)
			requireExcludedReason(t, "claudecode", ownStatusRowFor(t, api, "uid", "5003", "carol", "claudecode"), wantCode, wantText)
		})
	}
}
