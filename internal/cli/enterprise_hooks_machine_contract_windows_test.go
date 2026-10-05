// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The guardian passes one Claude machine-policy contract to every Claude row
// of a standalone manifest and none to Secure Client or other connectors.
func TestEnterpriseHookMachinePolicyContractIsStandaloneAndClaudeOnly(t *testing.T) {
	enabled := true
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode", AgentVersion: "2.1.230", Enabled: &enabled},
		{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", AgentVersion: "2.1.160", Enabled: &enabled},
	}}
	older := connector.ResolveHookContract("claudecode", "2.1.160").Contract.ContractID

	originalCfg := cfg
	t.Cleanup(func() { cfg = originalCfg })
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	machine := enterpriseHookMachinePolicyContract(manifest)
	if machine != older {
		t.Fatalf("standalone machine contract = %q, want %q", machine, older)
	}
	if got := enterpriseHookMachinePolicyContractFor("claudecode", machine); got != older {
		t.Fatalf("Claude row contract = %q, want %q", got, older)
	}
	if got := enterpriseHookMachinePolicyContractFor("codex", machine); got != "" {
		t.Fatalf("Codex row received a Claude machine contract %q", got)
	}

	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	if got := enterpriseHookMachinePolicyContract(manifest); got != "" {
		t.Fatalf("Secure Client machine contract = %q, want each row's own", got)
	}
}

// A single-target administrator install renders the shared Claude policy from
// the guardian manifest's deployment contract, not from its own row, so the
// next reconcile does not rewrite the body back.
func TestEnterpriseHookInstallMachinePolicyContractFollowsTheGuardianManifest(t *testing.T) {
	enabled := true
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001", Connector: "claudecode", UserHome: `C:\Users\a`, AgentVersion: "2.1.230", Enabled: &enabled},
		{SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", UserHome: `C:\Users\b`, AgentVersion: "2.1.160", Enabled: &enabled},
	}}
	older := connector.ResolveHookContract("claudecode", "2.1.160").Contract.ContractID
	newer := connector.ResolveHookContract("claudecode", "2.1.230").Contract.ContractID
	if older == "" || older == newer {
		t.Fatalf("fixture needs two Claude contracts, got %q and %q", older, newer)
	}
	path := filepath.Join(t.TempDir(), "targets.yaml")
	raw, err := yaml.Marshal(&manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	originalCfg := cfg
	originalPath := enterpriseHookStandaloneManifestPath
	originalTrust := enterpriseHookManifestFileTrustCheck
	t.Cleanup(func() {
		cfg = originalCfg
		enterpriseHookStandaloneManifestPath = originalPath
		enterpriseHookManifestFileTrustCheck = originalTrust
	})
	manifestPath := path
	enterpriseHookStandaloneManifestPath = func() (string, error) { return manifestPath, nil }
	trustChecked := ""
	enterpriseHookManifestFileTrustCheck = func(checked string) error {
		trustChecked = checked
		return nil
	}
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}

	got, err := enterpriseHookInstallMachinePolicyContract("claudecode")
	if err != nil || got != older {
		t.Fatalf("install contract = %q, %v; want the deployment contract %q", got, err, older)
	}
	if trustChecked != path {
		t.Fatalf("the guardian manifest must be trust-checked before it is read (checked %q)", trustChecked)
	}
	if got, err := enterpriseHookInstallMachinePolicyContract("codex"); got != "" || err != nil {
		t.Fatalf("Codex install received a Claude machine contract %q, %v", got, err)
	}

	// Before the guardian's first publication there is no deployment contract.
	manifestPath = filepath.Join(t.TempDir(), "missing.yaml")
	if got, err := enterpriseHookInstallMachinePolicyContract("claudecode"); got != "" || err != nil {
		t.Fatalf("missing manifest = %q, %v; want the row's own contract", got, err)
	}

	// A manifest that exists but cannot be read refuses the install.
	manifestPath = filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(manifestPath, []byte("targets: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := enterpriseHookInstallMachinePolicyContract("claudecode"); err == nil ||
		!strings.Contains(err.Error(), "machine-wide Claude contract") {
		t.Fatalf("unreadable manifest error = %v, want a refusal", err)
	}

	// Secure Client renders each row's own contract and reads nothing.
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	if got, err := enterpriseHookInstallMachinePolicyContract("claudecode"); got != "" || err != nil {
		t.Fatalf("Secure Client install contract = %q, %v; want none", got, err)
	}
}
