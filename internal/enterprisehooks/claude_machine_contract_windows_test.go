// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
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

// Under Secure Client the active policy is rendered from the enrolled row's
// own contract, which for Claude Code 2.1.219+ adds DirectoryAdded. The
// identity proof the Guardian runs before it stages a signed-out user's
// deferred row must still recognize that policy as this deployment's; it
// failed the whole install before.
func TestSecureClientClaudePolicyIdentityAcceptsTheRowContract(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	previousStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	t.Setenv(connector.WindowsGatewayServiceNameEnv, "DefenseClawGateway")

	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	body, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "DirectoryAdded") {
		t.Fatal("fixture must render the row's newer contract under Secure Client")
	}
	if err := VerifyWindowsClaudeManagedPolicyIdentity(fixture.hookExe, opts.APIAddr, "DefenseClawGateway"); err != nil {
		t.Fatalf("identity of the row-contract policy: %v", err)
	}
	other := filepath.Join(filepath.Dir(fixture.hookExe), "other-hook.exe")
	if err := VerifyWindowsClaudeManagedPolicyIdentity(other, opts.APIAddr, "DefenseClawGateway"); err == nil {
		t.Fatal("the policy was accepted for another hook executable")
	}
}

// Under Secure Client a signed-out account with no known Claude version (no
// client installed, or a profile whose account no longer resolves) renders
// the version-less contract. Staging its deferred row must keep the body
// already published for an enrolled account on a newer contract and only add
// the SID: replacing it dropped DirectoryAdded for every user, and the
// enrolled account's byte-for-byte verification then failed the install.
func TestSecureClientVersionlessDeferredClaudeRowKeepsThePublishedBody(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	previousStandalone := windowsEnterpriseStandaloneProcess
	previousSelector := windowsManagedRuntimeSelectorPathResolver
	selectorRoot := t.TempDir()
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(selectorRoot, name, windowsManagedRuntimeSelectorFile), nil
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsManagedRuntimeSelectorPathResolver = previousSelector
	})

	enrolled, err := windows.StringToSid("S-1-5-21-1004336348-1177238915-682003330-1999")
	if err != nil {
		t.Fatal(err)
	}
	setup := withWindowsClaudeManagedHooksOnly(connector.SetupOpts{
		APIAddr:                  "127.0.0.1:18970",
		HookFailMode:             canonicalHookFailMode(""),
		SecureClientHookDelivery: secureClientHookDelivery(),
		ManagedEnterprise:        true,
		HookExecutable:           fixture.hookExe,
		HookContractID:           connector.ResolveHookContract("claudecode", "2.1.230").Contract.ContractID,
	})
	published, err := connector.NewClaudeCodeConnector().ManagedHookPolicy(setup)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(published), "DirectoryAdded") {
		t.Fatal("fixture must publish the newer contract")
	}
	if _, _, err := installWindowsClaudeManagedPolicy(published, setup, enrolled); err != nil {
		t.Fatalf("publish the enrolled account's policy: %v", err)
	}

	// The signed-out account's own data folder, as the enumerator finds it.
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, dataDir, fixture.targetSID)
	if err := setWindowsUserPathProtection(dataDir, fixture.targetSID, true); err != nil {
		t.Fatalf("protect the pending data folder: %v", err)
	}
	enabled := true
	pending := ManifestTarget{
		SID: fixture.targetSID.String(), UserHome: fixture.home, DataDir: dataDir,
		Connector: "claudecode", Enabled: &enabled, Deferred: true,
	}
	manifest := Manifest{Version: 1, Targets: []ManifestTarget{
		pending,
		{SID: enrolled.String(), UserHome: `C:\Users\other`, DataDir: `C:\Users\other\.defenseclaw`, Connector: "claudecode", AgentVersion: "2.1.230", Enabled: &enabled},
	}}
	if err := StageWindowsEnterpriseDeferredPolicies(manifest, []ManifestTarget{pending}, "127.0.0.1:18970"); err != nil {
		t.Fatalf("stage the version-less deferred Claude row: %v", err)
	}
	body, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, published) {
		t.Fatal("staging the version-less row replaced the published body")
	}
	targets, active, err := ReadWindowsClaudeManagedPolicyTargets()
	if err != nil || !active {
		t.Fatalf("ReadWindowsClaudeManagedPolicyTargets = %v, %v, %v", targets, active, err)
	}
	want := map[string]bool{strings.ToUpper(enrolled.String()): false, strings.ToUpper(fixture.targetSID.String()): false}
	for _, sid := range targets {
		want[strings.ToUpper(sid)] = true
	}
	for sid, seen := range want {
		if !seen {
			t.Fatalf("enrolled SIDs %v miss %s", targets, sid)
		}
	}
}
