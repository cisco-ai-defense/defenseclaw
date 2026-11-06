// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// bareSetupRun is Setup named as a command in plain text.
var bareSetupRun = regexp.MustCompile(`(?i)(?:^|[^'.\\])DefenseClawSetup-Enterprise-Standalone-x64\.exe\s+/[a-z]|\bSetup\s+/(?:repair|ensure|uninstall|install|upgrade|reconcile|recover|verify)\b`)

// cowork-1-0-8 GAP-0095: Setup is not installed on a managed Windows
// computer, so a hint that sends an administrator to it runs it from the
// folder that holds it and says where it comes from. Each producer below
// printed the bare file name ("DefenseClawSetup-Enterprise-Standalone-x64.exe
// /repair JSON=1") or "Setup /ensure".
func TestWindowsEnterpriseSetupHintsRunAsTypedAndSayWhereSetupComes(t *testing.T) {
	setup := "& '.\\" + managed.WindowsStandaloneSetupName + "'"
	original := windowsEnterpriseRunningAsLocalSystem
	t.Cleanup(func() { windowsEnterpriseRunningAsLocalSystem = original })
	hints := map[string]string{
		"owner next step":    windowsEnterpriseDeploymentRecordOwnerNextStep(),
		"missing artifact":   windowsEnterpriseMissingArtifactNextStep("recorded managed artifact is missing: C:\\x", false),
		"pending inspection": windowsEnterprisePendingInspectionStep(`C:\stage\config.yaml`),
		"local system":       windowsEnterpriseLocalSystemRemedy("/uninstall PURGE=1"),
		"untrusted record": windowsEnterpriseUntrustedDeploymentRecordMessage(windowsEnterpriseIgnoredDeploymentRecord{
			profile: "standalone", path: `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`, reason: "reparse point"}),
		"no agent target": windowsEnterpriseNoAgentTargetReason(),
	}
	for _, system := range []bool{false, true} {
		windowsEnterpriseRunningAsLocalSystem = func() bool { return system }
		for _, action := range []string{"ensure", "repair", "uninstall"} {
			hints["next step "+action+" busy"] = windowsEnterpriseStandaloneNextStep(action, `C:\stage\config.yaml`, false, true, false, true, nil, nil, nil)
			hints["next step "+action+" pending"] = windowsEnterpriseStandaloneNextStep(action, `C:\stage\config.yaml`, false, false, false, true, nil, nil, nil)
		}
		hints["next step forced"] = windowsEnterpriseStandaloneNextStep("uninstall", "", false, false, true, true, nil, nil, nil)
		for _, code := range []string{"not_local_system", "same_binary", "untrusted", "older_release", "version_unknown"} {
			hints["next step "+code] = windowsEnterpriseStandaloneNextStep("ensure", "", false, false, false, true, nil,
				&windowsEnterpriseRecoveryGatewayRefusal{Code: code}, nil)
		}
	}
	for name, hint := range hints {
		if bareSetupRun.MatchString(hint) {
			t.Errorf("%s names Setup as a bare command: %s", name, hint)
		}
	}
	for name, hint := range hints {
		if name == "no agent target" {
			if !strings.Contains(hint, setup+" /ensure") || !strings.Contains(hint, managed.WindowsSetupSource) {
				t.Errorf("%s: %s", name, hint)
			}
			continue
		}
		if !strings.Contains(hint, setup+" /") {
			t.Errorf("%s does not run Setup from its folder (%s /...): %s", name, setup, hint)
		}
		if !strings.Contains(hint, managed.WindowsSetupSource) {
			t.Errorf("%s does not say where Setup comes from: %s", name, hint)
		}
	}
}

// The installed CLI is on the computer, Setup is not: a hint for what the
// CLI does without a payload names the CLI by its full path, and no longer
// names Setup beside it (cowork-1-0-8 GAP-0095).
func TestWindowsEnterpriseHintsNameTheInstalledCLIWhereItDoesTheWork(t *testing.T) {
	repair := windowsEnterpriseAdminCommand("repair")
	stopped := windowsEnterpriseStoppedServiceNextStep([]enterprisestatus.Service{{Name: "DefenseClawGateway", State: "stopped", Required: true}})
	if !strings.Contains(stopped, repair) || strings.Contains(stopped, "Setup") || strings.Contains(stopped, ".exe /") {
		t.Fatalf("stopped service next step = %q", stopped)
	}
	if hint := windowsClaudeAttestationHint(); !strings.Contains(hint, "--attest-claude-effective-policy") || strings.Contains(hint, "Setup") {
		t.Fatalf("attestation hint = %q", hint)
	}
}

// Secure Client text is byte for byte what it was.
func TestWindowsEnterpriseSecureClientHintsAreUnchanged(t *testing.T) {
	got := windowsEnterpriseUntrustedDeploymentRecordMessage(windowsEnterpriseIgnoredDeploymentRecord{
		profile: "secure_client", path: `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`, reason: "owner mismatch"})
	want := `ignored a deployment record an administrator did not write: C:\ProgramData\Cisco\DefenseClaw\install\deployment.json: owner mismatch`
	if got != want {
		t.Fatalf("Secure Client record warning = %q, want %q", got, want)
	}
}
