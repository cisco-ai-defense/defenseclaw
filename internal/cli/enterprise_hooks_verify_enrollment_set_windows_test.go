//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0790: with one account skipped because an administrator owns a link at
// its DefenseClaw folder, the Guardian publishes the Claude and Codex SIDs of
// every other account only. Verify must expect exactly that set: the whole
// enabled manifest names the skipped account and failed the machine.
func TestWindowsVerifyEnrollmentSetExcludesOnlyTheSkippedAccount(t *testing.T) {
	const alice = "S-1-5-21-111-222-333-1001"
	const bob = "S-1-5-21-111-222-333-1002"
	homes := map[string]string{alice: `C:\Users\alice`, bob: `C:\Users\bob`}
	manifest := enterprisehooks.Manifest{Version: 1}
	for _, sid := range []string{alice, bob} {
		for _, connectorName := range []string{"claudecode", "codex"} {
			manifest.Targets = append(manifest.Targets, enterprisehooks.ManifestTarget{
				SID: sid, UserHome: homes[sid], Connector: connectorName,
			})
		}
	}
	previousCfg := cfg
	previousClaudeReader := enterpriseHookClaudePolicyTargetsReader
	previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
	previousCursorReader := enterpriseHookCursorPolicyTargetsReader
	previousClaudeIdentity, previousCursorIdentity := enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookClaudePolicyTargetsReader = previousClaudeReader
		enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
		enterpriseHookCursorPolicyTargetsReader = previousCursorReader
		enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier = previousClaudeIdentity, previousCursorIdentity
	})
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Connector: "claudecode"},
	}
	var registered []string
	enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) {
		return append([]string(nil), registered...), true, nil
	}
	enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
		return connector.WindowsCodexMachineRequirementsOptions{
			HookBinary:  `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
			GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway",
		}, nil
	}
	enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
		targets := []connector.WindowsCodexManagedRuntimeTarget{}
		for _, sid := range registered {
			targets = append(targets, connector.WindowsCodexManagedRuntimeTarget{
				SID: sid, DataDir: filepath.Join(homes[sid], ".defenseclaw"),
			})
		}
		return connector.WindowsCodexManagedRuntimeRegistry{
			Active: true, Targets: targets,
			GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway",
		}, nil
	}
	enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
		return nil, false, nil
	}
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }

	// The Guardian left alice out: she failed, never protected.
	skipped := map[string]struct{}{}
	for _, target := range manifest.Targets {
		if target.SID == alice {
			enterpriseHookNoteExcusedUnenrolled(skipped, target, false)
		}
	}
	expected := enterpriseHookEnrollmentManifest(manifest, skipped)
	registered = []string{bob}
	if err := verifyEnterpriseHookManagedEnrollments(expected, "127.0.0.1:32109"); err != nil {
		t.Fatalf("the published set without the skipped account failed verify: %v", err)
	}
	// Before the fix verify expected the whole manifest.
	if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err == nil {
		t.Fatal("the whole manifest accepted a published set without the skipped account")
	}
	// Controls: an account that is not skipped and is missing still fails, and
	// so does a skipped account that is still enrolled.
	registered = nil
	if err := verifyEnterpriseHookManagedEnrollments(expected, "127.0.0.1:32109"); err == nil {
		t.Fatal("an uncovered account that is not skipped passed verify")
	}
	registered = []string{alice, bob}
	if err := verifyEnterpriseHookManagedEnrollments(expected, "127.0.0.1:32109"); err == nil {
		t.Fatal("a skipped account that is still enrolled passed verify")
	}
	// A skipped account an earlier release protected stays enrolled.
	kept := map[string]struct{}{}
	for _, target := range manifest.Targets {
		if target.SID == alice {
			enterpriseHookNoteExcusedUnenrolled(kept, target, true)
		}
	}
	if err := verifyEnterpriseHookManagedEnrollments(enterpriseHookEnrollmentManifest(manifest, kept), "127.0.0.1:32109"); err != nil {
		t.Fatalf("a protected skipped account lost its expected enrollment: %v", err)
	}
}
