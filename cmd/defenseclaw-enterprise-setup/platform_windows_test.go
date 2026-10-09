// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		"--acp-binary", filepath.Join(stage, "defenseclaw-acp.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--sensor-helper-binary", filepath.Join(stage, "defenseclaw-sensor-helper.exe"),
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

func TestEnterpriseLifecycleArgumentsForStandalonePayload(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	signer := "ab" + strings.Repeat("0", 62)
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{
		Action:             "ensure",
		Config:             `C:\staging\config.yaml`,
		JSON:               true,
		Standalone:         true,
		StandaloneUnsigned: true,
		ProductVersion:     "1.4.0",
		AllowedSigners:     strings.ToUpper(signer),
	})
	want := []string{
		"enterprise", "windows", "ensure",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--acp-binary", filepath.Join(stage, "defenseclaw-acp.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--sensor-helper-binary", filepath.Join(stage, "defenseclaw-sensor-helper.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", `C:\staging\config.yaml`,
		// --bootstrap-parent is unconditional post-#839 (Authenticode-
		// aware trailer reader + protected bootstrap parent): the
		// standalone and Secure Client lifecycles both spin up the
		// isolated bootstrap environment, so this flag is forwarded for
		// every action and flavor.
		"--bootstrap-parent", filepath.Join(stage, enterpriseSetupScratchDirName),
		"--json",
		"--profile", "standalone",
		"--product-version", "1.4.0",
		"--trust-mode", "hash_pinned",
		"--payload-manifest", filepath.Join(stage, standalonePayloadTrustName),
		"--allowed-signer", signer,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestStandaloneSetupReportsMalformedInputPathsAsInvalidArguments(t *testing.T) {
	for _, value := range []string{
		"config.yaml",
		` C:\dc\config.yaml`,
		`%ProgramData%\config.yaml`,
		filepath.Join(t.TempDir(), "missing", "config.yaml"),
	} {
		_, err := validateEnterpriseSetupInput(value, "config")
		if err == nil {
			t.Fatalf("%q accepted", value)
		}
		var invalid enterpriseSetupInvalidArguments
		if standalone := standaloneEnterpriseSetupInputError(true, err); !errors.As(standalone, &invalid) || standalone.Error() != err.Error() {
			t.Fatalf("%q: standalone error %v is not invalid arguments with the same text", value, standalone)
		}
		if secureClient := standaloneEnterpriseSetupInputError(false, err); errors.As(secureClient, &invalid) || secureClient != err {
			t.Fatalf("%q: Secure Client error changed: %v", value, secureClient)
		}
	}
	// An existing input that fails the trust check is a security refusal
	// (1603), not a command-line error, for either flavor.
	untrusted := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(untrusted, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := validateEnterpriseSetupInput(untrusted, "config")
	var invalid enterpriseSetupInvalidArguments
	if err == nil || errors.As(standaloneEnterpriseSetupInputError(true, err), &invalid) {
		t.Fatalf("untrusted config: %v", err)
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
