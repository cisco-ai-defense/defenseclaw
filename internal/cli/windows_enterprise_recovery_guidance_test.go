// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Verify with the guardian stopped names the repair that starts it again
// (GAP-1072); with every service running it adds nothing.
func TestWindowsEnterpriseStoppedServiceNextStep(t *testing.T) {
	services := []enterprisestatus.Service{
		{Name: "DefenseClawGateway", Kind: "gateway", State: "running", Required: true},
		{Name: "DefenseClawHookGuardian", Kind: "guardian", State: "stopped", Required: true},
	}
	got := windowsEnterpriseStoppedServiceNextStep(services)
	// GAP-1338: the repair names the installed CLI, which Setup keeps off PATH.
	for _, want := range []string{"Next step:", "& '" + managedWindowsAdminCLI() + "' enterprise windows repair --profile standalone", "/repair JSON=1", "start DefenseClawHookGuardian again"} {
		if !strings.Contains(got, want) {
			t.Fatalf("next step %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "DefenseClawGateway") {
		t.Fatalf("next step names a running service: %q", got)
	}
	services[1].State = "running"
	if got := windowsEnterpriseStoppedServiceNextStep(services); got != "" {
		t.Fatalf("all running, next step = %q", got)
	}
}

// GAP-1184: a stopped gateway is named instead of "installer exit 1".
func TestWindowsEnterpriseNotHealthyMessageNamesTheStoppedService(t *testing.T) {
	services := []enterprisestatus.Service{
		{Name: "DefenseClawGateway", Kind: "gateway", State: "stopped", Required: true},
		{Name: "DefenseClawHookGuardian", Kind: "guardian", State: "running", Required: true},
	}
	got := windowsEnterpriseNotHealthyMessage(services, 1)
	if !strings.Contains(got, "the DefenseClawGateway service is stopped") || strings.Contains(got, "installer exit") {
		t.Fatalf("not healthy message = %q", got)
	}
	services[0].State = "running"
	if got := windowsEnterpriseNotHealthyMessage(services, 1); !strings.Contains(got, "& '"+managedWindowsAdminCLI()+"' enterprise windows verify --profile standalone") || strings.Contains(got, "installer exit") {
		t.Fatalf("no stopped service, message = %q", got)
	}
}

// GAP-1276: the enumerator's rule-pack error leads, without its log line.
func TestWindowsEnterpriseEnumeratorFailureTextUnwrapsTheCause(t *testing.T) {
	message := `synchronous target enumeration failed with exit 1603: [hook-enumerator] windows: manifest=C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml interval=5m0s once=true initial_delay=30s ` +
		`Error: enterprise windows enumerate: load config: config: managed standalone guardrail.rule_pack_dir C:\pack: the gateway service account NT SERVICE\DefenseClawGateway cannot read C:\pack; grant it Read & execute, for example: icacls "C:\pack" /grant "NT SERVICE\DefenseClawGateway:(OI)(CI)RX" /T`
	text, code, ok := windowsEnterpriseEnumeratorFailureText(message)
	if !ok || code != "rule_pack_unreadable" {
		t.Fatalf("ok=%t code=%q", ok, code)
	}
	if !strings.HasPrefix(text, `the managed config's guardrail.rule_pack_dir C:\pack: the gateway service account NT SERVICE\DefenseClawGateway cannot read`) ||
		!strings.Contains(text, "icacls") || strings.Contains(text, "hook-enumerator") {
		t.Fatalf("text = %q", text)
	}
	if _, _, ok := windowsEnterpriseEnumeratorFailureText("the gateway did not start"); ok {
		t.Fatal("an unrelated message was rewritten")
	}
	// The v9 keys get the code too; a policy_dir the service cannot read
	// does not (GAP-0314).
	for label, want := range map[string]string{
		"guardrail.rule_pack": "rule_pack_unreadable", "guardrail.custom_packs.acme.path": "rule_pack_unreadable", "policy_dir": "",
	} {
		v9 := strings.Replace(message, "guardrail.rule_pack_dir", label, 1)
		if _, code, ok := windowsEnterpriseEnumeratorFailureText(v9); !ok || code != want {
			t.Fatalf("%s: ok=%t code=%q, want %q", label, ok, code, want)
		}
	}
}

// GAP-1419: a refused managed runtime bundle names the file and the reason
// and gives a next step; other errors get nothing added.
func TestWindowsEnterpriseInvalidRuntimeBundleNextStep(t *testing.T) {
	failure := `managed-hook lifecycle snapshot retire failed: retire kiro managed runtime generations for SID S-1-5-21-1-2-3-1017 (HOST\alice): ` +
		`enterprise hooks: refusing to collect an invalid managed runtime bundle: C:\Users\alice\.defenseclaw\hooks\kiro-1.json: ` +
		`managed runtime gateway address is not canonical`
	next := windowsEnterpriseInvalidRuntimeBundleNextStep(failure)
	for _, want := range []string{`leave C:\Users\alice\.defenseclaw\hooks\kiro-1.json in place`, `enterprise-lifecycle.log`, "Next step:"} {
		if !strings.Contains(next, want) {
			t.Fatalf("next step %q does not contain %q", next, want)
		}
	}
	if got := windowsEnterpriseInvalidRuntimeBundleNextStep("gateway did not become ready"); got != "" {
		t.Fatalf("an unrelated error got %q", got)
	}
}

// GAP-1658: a CLI from another build than the installed DefenseClaw says so
// and names the installed CLI, instead of the module digest alone.
func TestWindowsEnterpriseInstallerBuildMismatchText(t *testing.T) {
	failure := `DefenseClaw enterprise installer rejected its module before import: DefenseClaw enterprise installer module SHA-256 ` +
		`does not match the pinned payload manifest: C:\ProgramData\DefenseClaw-Installer-0f\DefenseClawEnterprise.psm1`
	text, ok := windowsEnterpriseInstallerBuildMismatchText(failure, "uninstall", true)
	if !ok {
		t.Fatal("the module pin refusal was not recognized")
	}
	for _, want := range []string{"does not match the installed DefenseClaw", "stopped before it changed anything",
		`\Cisco\DefenseClaw\bin\defenseclaw.exe' enterprise windows uninstall --purge --profile standalone`} {
		if !strings.Contains(text, want) {
			t.Fatalf("text %q does not contain %q", text, want)
		}
	}
	if _, ok := windowsEnterpriseInstallerBuildMismatchText("gateway did not become ready", "uninstall", false); ok {
		t.Fatal("an unrelated error was rewritten")
	}
}

// GAP-0920: a LocalSystem run whose recovery failed is not told to run the
// same LocalSystem Setup command again; it is told to correct the named
// cause first.
func TestWindowsEnterpriseStandaloneNextStepAfterALocalSystemRecovery(t *testing.T) {
	original := windowsEnterpriseRunningAsLocalSystem
	t.Cleanup(func() { windowsEnterpriseRunningAsLocalSystem = original })
	windowsEnterpriseRunningAsLocalSystem = func() bool { return true }
	got := windowsEnterpriseStandaloneNextStep("ensure", `C:\stage\config.yaml`, false, true, nil, nil)
	if strings.Contains(got, "Next step: run DefenseClaw Setup") || !strings.Contains(got, "running it again unchanged fails the same way") ||
		!strings.Contains(got, `/ensure CONFIG=C:\stage\config.yaml JSON=1`) {
		t.Fatalf("next step = %q", got)
	}
	windowsEnterpriseRunningAsLocalSystem = func() bool { return false }
	if got := windowsEnterpriseStandaloneNextStep("ensure", `C:\stage\config.yaml`, false, true, nil, nil); !strings.Contains(got, "Next step: run DefenseClaw Setup") {
		t.Fatalf("an administrator run lost the LocalSystem step: %q", got)
	}
}

// GAP-0741: a committed install whose lifecycle journal could not be retired
// because of a per-user .defenseclaw folder says it is installed, names the
// folder and its fix, and says that /ensure again converges.
func TestWindowsEnterpriseCommittedJournalNextStep(t *testing.T) {
	original := `Install committed, but its protected managed-hook lifecycle journal could not be retired: retire copilot managed runtime generations for SID S-1-5-21-1-2-3-1018: enterprise hooks: managed runtime generation directory is untrusted: C:\Users\dcw-std2\.defenseclaw\hooks: access denied`
	step := windowsEnterpriseCommittedJournalNextStep(original, true)
	for _, want := range []string{"installed and running", `C:\Users\dcw-std2\.defenseclaw was left by a per-user`, "uninstall --all --binaries --yes", "run Setup /ensure again"} {
		if !strings.Contains(step, want) {
			t.Fatalf("next step %q, want %q", step, want)
		}
	}
	if got := windowsEnterpriseCommittedJournalNextStep(original, false); got != "" {
		t.Fatalf("not installed: %q", got)
	}
}

// GAP-0770: a lifecycle that a Group Policy AllSigned execution policy kept
// from starting names the policy and the signature cause, with the fix,
// instead of "exited with code 1".
func TestWindowsEnterpriseExecutionPolicyRefusal(t *testing.T) {
	stderr := []byte("\x1b[31;1mSecurityError: File C:\\ProgramData\\DefenseClaw-Setup-1\\install-enterprise.ps1 cannot be loaded. The file C:\\ProgramData\\DefenseClaw-Setup-1\\install-enterprise.ps1 is not digitally signed. You cannot run this script on the current system.\x1b[0m\r\n")
	got := windowsEnterpriseExecutionPolicyRefusal(stderr)
	for _, want := range []string{"powershell_execution_policy: ", "is not digitally signed", "AllSigned", "Trusted Publishers", "nothing was changed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("refusal %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("refusal keeps color sequences: %q", got)
	}
	if got := windowsEnterpriseExecutionPolicyRefusal([]byte("powershell7_required: install PowerShell 7\n")); got != "" {
		t.Fatalf("other stderr = %q", got)
	}
}
