// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Copilot loads every effective JSON drop-in of policy.d, so the published
// hook stays registered when it sits in a sibling file. The status of an
// excluded account may say DefenseClaw does not inspect its calls only when no
// effective drop-in names a DefenseClaw hook; a source it cannot parse is not
// absence either.
func TestOwnStatusExcludedCopilotHookInAnyEffectiveDropIn(t *testing.T) {
	opts := enterprisepolicy.Options{GOOS: "linux", Root: t.TempDir(), SkipTrustChecks: true}
	publishPolicyViewTestConnector(t, opts, "copilot")
	dir, err := enterprisepolicy.CopilotPolicyDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, enterprisepolicy.DefenseClawDropInName)
	sibling := filepath.Join(dir, "91-policy.json")
	registered, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sibling, registered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"carol"}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"copilot": {}}
	api := NewAPIServer(":0", nil, nil, nil, nil, cfg)
	api.managedHookAuthz.Store(newManagedHookAuthorizer(cfg.Enterprise.Enrollment, nil,
		func() (managedHookLedger, error) { return managedHookLedger{}, nil }))
	saved := managedPolicyViewOptions
	managedPolicyViewOptions = func(string) (enterprisepolicy.Options, string, bool) { return opts, "", true }
	t.Cleanup(func() { managedPolicyViewOptions = saved })
	copilotRow := func() map[string]any {
		rows, _ := ownExcludedRowsOf(t, api, "uid", "5003", "carol")
		return rows["copilot"]
	}

	requireExcludedReason(t, "hook moved to a sibling drop-in", copilotRow(), unknownCode, unknownReason)

	// A sibling Copilot cannot parse is a source nobody examined.
	if err := os.WriteFile(filepath.Join(dir, "92-broken.json"), []byte("{\"hooks\": "), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}
	requireExcludedReason(t, "unparsable sibling drop-in", copilotRow(), unknownCode, unknownReason)

	// Benign twin: every effective drop-in was read and none names a
	// DefenseClaw hook, so nothing inspects the calls.
	if err := os.WriteFile(filepath.Join(dir, "92-broken.json"), []byte("{\"hooks\": {}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requireExcludedReason(t, "no DefenseClaw hook in any drop-in", copilotRow(), nothingCode, nothingReason)
}
