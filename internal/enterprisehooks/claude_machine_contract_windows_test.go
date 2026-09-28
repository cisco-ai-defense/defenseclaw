// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// In standalone, a Claude row whose own version selects the newer contract
// installs and verifies the deployment-wide body instead: one user's version
// can no longer switch the shared policy, and rows on different contracts no
// longer rewrite it in turn.
func TestStandaloneClaudeInstallRendersTheDeploymentContract(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	previousStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })

	older := connector.ResolveHookContract("claudecode", "2.1.187").Contract.ContractID
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if own := connector.ResolveHookContract("claudecode", opts.AgentVersion).Contract.ContractID; own == older {
		t.Fatalf("fixture row must resolve to a newer contract than %s", older)
	}
	opts.MachinePolicyContractID = older

	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	body, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "DirectoryAdded") {
		t.Fatal("the machine policy was rendered from the row's own newer contract, not the deployment contract")
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify against the deployment contract: %v", err)
	}

	ownContract := opts
	ownContract.MachinePolicyContractID = ""
	if _, err := Verify(context.Background(), ownContract); err == nil ||
		!strings.Contains(err.Error(), "differs from the canonical DefenseClaw hook matrix") {
		t.Fatalf("Verify against the row's own contract = %v, want the canonical-body mismatch", err)
	}
}

// Staging a signed-out user's deferred row renders the same deployment-wide
// body, never the pending row's own self-reported contract.
func TestStandaloneDeferredClaudeStagingRendersTheDeploymentContract(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	previousStandalone := windowsEnterpriseStandaloneProcess
	previousSelector := windowsManagedRuntimeSelectorPathResolver
	selectorRoot := t.TempDir()
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(selectorRoot, name, windowsManagedRuntimeSelectorFile), nil
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsManagedRuntimeSelectorPathResolver = previousSelector
	})

	enabled := true
	pending := ManifestTarget{
		SID: fixture.targetSID.String(), UserHome: fixture.home, DataDir: filepath.Join(fixture.home, ".defenseclaw"),
		Connector: "claudecode", AgentVersion: "2.1.230", Enabled: &enabled, Deferred: true,
	}
	manifest := Manifest{Version: 1, Targets: []ManifestTarget{
		pending,
		// Another enrolled user on the older contract.
		{SID: "S-1-5-21-1004336348-1177238915-682003330-1999", UserHome: `C:\Users\other`, DataDir: `C:\Users\other\.defenseclaw`, Connector: "claudecode", AgentVersion: "2.1.187", Enabled: &enabled},
	}}
	if err := StageWindowsEnterpriseDeferredPolicies(manifest, []ManifestTarget{pending}, "127.0.0.1:18970"); err != nil {
		t.Fatalf("stage deferred Claude row: %v", err)
	}
	body, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "DirectoryAdded") {
		t.Fatal("staging rendered the pending row's own newer contract instead of the deployment contract")
	}
}
