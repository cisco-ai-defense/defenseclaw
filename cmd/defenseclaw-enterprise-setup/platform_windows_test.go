// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestEnterpriseLifecycleArgumentsUsePublicMachineTransaction(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	opts := enterpriseSetupOptions{
		Action:                        "install",
		Config:                        `C:\staging\config.yaml`,
		Manifest:                      `C:\staging\targets.yaml`,
		AttestAgentApplicationControl: true,
		AttestClaudeEffectivePolicy:   true,
		NoStart:                       true,
		JSON:                          true,
	}
	want := []string{
		"enterprise", "windows", "install",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--broker-binary", filepath.Join(stage, "defenseclaw-cmid-broker.exe"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", opts.Config,
		"--manifest", opts.Manifest,
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--no-start", "--json",
		"--attest-agent-application-control",
		"--attest-claude-effective-policy",
	}
	if got := enterpriseLifecycleArguments(stage, opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestEnterpriseLifecycleReadOnlyDoesNotSupplyReplacementArtifacts(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: "status", JSON: true})
	want := []string{
		"enterprise", "windows", "status",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

// The outer signed DefenseClawSetup EXE always forwards its own protected
// %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch directory as
// install-enterprise.ps1's -BootstrapParent, so the one-shot bootstrap
// dir does not land under C:\Windows\Temp. On Azure-AD-joined hosts,
// C:\Windows\Temp carries an inherited Allow ACE for the interactive AAD
// principal with replacement rights, which fails the module's later
// trusted-ancestor walk on rendered YAML content.
func TestEnterpriseLifecycleArgumentsAlwaysForwardsBootstrapParent(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	wantParent := filepath.Join(stage, enterpriseSetupScratchDirName)
	for _, action := range []string{"install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: action})
			foundIndex := -1
			for index := 0; index < len(got)-1; index++ {
				if got[index] == "--bootstrap-parent" {
					foundIndex = index
					break
				}
			}
			if foundIndex < 0 {
				t.Fatalf("%s: --bootstrap-parent missing from args: %#v", action, got)
			}
			if got[foundIndex+1] != wantParent {
				t.Fatalf("%s: --bootstrap-parent value = %q, want %q", action, got[foundIndex+1], wantParent)
			}
		})
	}
}
