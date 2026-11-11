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
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsEnterpriseDeploymentRecordOwnerMessages(t *testing.T) {
	record := `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`
	mismatch := "managed path owner/group do not match the exact canonical descriptor after ACL replacement: " + record
	next := windowsEnterpriseDeploymentRecordOwnerNextStep()
	for _, message := range []string{
		windowsEnterpriseUntrustedDeploymentRecordMessage(windowsEnterpriseIgnoredDeploymentRecord{
			profile: "standalone", path: record, reason: record + ": owner S-1-5-21-1001 is not trusted",
		}),
		mismatch + windowsEnterpriseRecordOwnerMismatchNextStep(mismatch),
	} {
		if !strings.Contains(message, record) || !strings.HasSuffix(message, next) {
			t.Fatalf("message does not name the record and shared next step: %q", message)
		}
	}
	for _, want := range []string{
		"inspect the deployment record owner", "restore its expected owner",
		"/uninstall FORCE=1 PURGE=1 JSON=1", "/ensure 'CONFIG=<config.yaml>' JSON=1",
		"& '.\\DefenseClawSetup-Enterprise-Standalone-x64.exe' /uninstall", managed.WindowsSetupSource,
	} {
		if !strings.Contains(next, want) {
			t.Fatalf("next step %q does not name %q", next, want)
		}
	}
	if got := windowsEnterpriseRecordOwnerMismatchNextStep("managed path owner/group do not match the exact canonical descriptor after ACL replacement: C:\\ProgramData\\Cisco\\DefenseClaw\\etc\\config.yaml"); got != "" {
		t.Fatalf("unrelated path gained record remedy: %q", got)
	}
}

func TestWindowsEnterpriseConfigRecoveryGuidance(t *testing.T) {
	for _, tc := range []struct {
		name, profile, platform string
		bundle                  bool
		want                    string
	}{
		{name: "signed bundle", profile: "standalone", platform: "windows", bundle: true, want: "enterprise windows repair"},
		{name: "standalone config", profile: "standalone", platform: "windows", want: "/ensure 'CONFIG="},
		{name: "secure client", profile: "secure_client", platform: "windows", bundle: true, want: "/ensure CONFIG="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := enterprisestatus.New("verify", tc.profile, tc.platform, "1.0.9")
			input := "config generation is unproven or records a hand edit; run " +
				windowsEnterpriseSetupCommand("/ensure", "CONFIG=<approved absolute config path>", "JSON=1") + " from an elevated PowerShell prompt."
			if tc.profile == "secure_client" {
				// Secure Client keeps the text it always had, byte for byte.
				input = "config generation is unproven or records a hand edit; run DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=<approved absolute config path> JSON=1 from an elevated prompt"
			}
			result.AddError("lifecycle_error", input)
			windowsEnterpriseConfigRecoveryGuidance(result, tc.bundle)
			if len(result.Errors) != 1 || !strings.Contains(result.Errors[0].Message, tc.want) {
				t.Fatalf("recovery errors = %+v, want %s", result.Errors, tc.want)
			}
			if tc.profile == "secure_client" && result.Errors[0].Message != input {
				t.Fatalf("Secure Client text changed: %q", result.Errors[0].Message)
			}
			// Setup /repair names the installed CLI repair for a deployment that
			// stored a bundle, so the CLI text must not send the operator back
			// to it (the two named each other and neither recovered).
			if tc.bundle && tc.profile == "standalone" && (strings.Contains(result.Errors[0].Message, "/repair") || strings.Contains(result.Errors[0].Message, "Setup")) {
				t.Fatalf("bundle recovery names Setup again: %q", result.Errors[0].Message)
			}
		})
	}
}

func TestWindowsEnterpriseUntrustedDeploymentRecordCases(t *testing.T) {
	standalone := `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`
	secureClient := `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\install\deployment.json`
	for _, tc := range []struct {
		name, profile, path, reason string
		want                        []string
		absent                      []string
		exact                       string
	}{
		{
			name:    "secure client record",
			profile: "secure_client", path: secureClient,
			reason: secureClient + `: owner S-1-5-21-1001 is not trusted`,
			exact:  "ignored a deployment record an administrator did not write: " + secureClient + `: ` + secureClient + `: owner S-1-5-21-1001 is not trusted`,
			absent: []string{"Standalone", "/uninstall", "/ensure", "Next step:"},
		},
		{
			name:    "standalone owner",
			profile: "standalone", path: standalone,
			reason: standalone + `: owner S-1-5-21-1001 is not trusted`,
			want:   []string{"inspect the deployment record owner", "restore its expected owner and group", "/uninstall FORCE=1 PURGE=1 JSON=1", "/ensure 'CONFIG=<config.yaml>' JSON=1", managed.WindowsSetupSource},
		},
		{
			name:    "standalone unsafe ACL",
			profile: "standalone", path: standalone,
			reason: standalone + `: untrusted Windows principal S-1-5-21-1001 has write-like access mask 0x2`,
			want:   []string{"unsafe permissions", "StateRoot", "remove the untrusted deployment record", "/ensure 'CONFIG=<config.yaml>' JSON=1", managed.WindowsSetupSource},
			absent: []string{"restore its expected owner", "If /ensure still refuses"},
		},
		{
			name:    "standalone reparse point",
			profile: "standalone", path: standalone,
			reason: standalone + `: reparse points are not allowed in enterprise deployment record path`,
			want:   []string{"reparse point", "StateRoot", "remove the untrusted deployment record", "/ensure 'CONFIG=<config.yaml>' JSON=1", managed.WindowsSetupSource},
			absent: []string{"restore its expected owner", "If /ensure still refuses"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsEnterpriseUntrustedDeploymentRecordMessage(windowsEnterpriseIgnoredDeploymentRecord{
				profile: tc.profile, path: tc.path, reason: tc.reason,
			})
			if tc.exact != "" && got != tc.exact {
				t.Fatalf("message = %q, want exact %q", got, tc.exact)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("message %q lacks %q", got, want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Fatalf("message %q contains %q", got, absent)
				}
			}
		})
	}
}

// Verify with the guardian stopped names the repair that starts it again
// (GAP-1072); with every service running it adds nothing.
func TestWindowsEnterpriseStoppedServiceNextStep(t *testing.T) {
	services := []enterprisestatus.Service{
		{Name: "DefenseClawGateway", Kind: "gateway", State: "running", Required: true},
		{Name: "DefenseClawHookGuardian", Kind: "guardian", State: "stopped", Required: true},
	}
	got := windowsEnterpriseStoppedServiceNextStep(services)
	// GAP-1338: the repair names the installed CLI, which Setup keeps off PATH.
	for _, want := range []string{"Next step:", "& '" + managedWindowsAdminCLI() + "' enterprise windows repair --profile standalone", "start DefenseClawHookGuardian again"} {
		if !strings.Contains(got, want) {
			t.Fatalf("next step %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "DefenseClawGateway") {
		t.Fatalf("next step names a running service: %q", got)
	}
	// GAP-0095: Setup is not installed on the computer, so it is not named.
	if strings.Contains(got, "Setup") || strings.Contains(got, "/repair JSON=1") {
		t.Fatalf("next step names a Setup that is not installed: %q", got)
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

// GAP-0314: every rule-pack setting the gateway service account cannot read
// is rule_pack_unreadable, whichever check refused it: the config check
// refuses a guardrail.custom_packs path that no setting selects, and the
// folder-above-the-pack form too. A pack a standard user can write and a
// policy_dir keep their own codes.
func TestWindowsEnterpriseRulePackUnreadableCoversEveryRulePackSetting(t *testing.T) {
	const account = `NT SERVICE\DefenseClawGateway`
	unselected := `invalid_arguments: config: managed standalone guardrail.custom_packs.acme.path C:\packs\acme: the gateway service account ` +
		account + ` cannot read C:\packs\acme; grant it Read & execute on the folder and let everything in it inherit that; fix it and run again (nothing was changed)`
	parent := `invalid_arguments: config: managed standalone guardrail.custom_packs.acme.path C:\packs\acme: the gateway service account ` +
		account + ` cannot list or read the permissions of the parent folder C:\packs; grant it Read & execute on that folder`
	for message, want := range map[string]bool{
		unselected: true,
		parent:     true,
		strings.Replace(unselected, "guardrail.custom_packs.acme.path", "guardrail.connectors.codex.rule_pack", 1): true,
		standaloneRulePackUnreadableText + ` that C:\cfg.yaml names: guardrail.rule_pack C:\packs\strict`:          true,
		strings.Replace(unselected, "guardrail.custom_packs.acme.path", "policy_dir", 1):                           false,
		`invalid_arguments: config: managed standalone guardrail.custom_packs.acme.path is not administrator-controlled: ` +
			`BUILTIN\Users (S-1-5-32-545) can write to C:\packs\acme`: false,
		`invalid_arguments: the config does not compile`: false,
	} {
		if got := windowsEnterpriseRulePackUnreadable(message); got != want {
			t.Errorf("windowsEnterpriseRulePackUnreadable(%q) = %t, want %t", message, got, want)
		}
	}
	enumerator := `synchronous target enumeration failed with exit 1603: [hook-enumerator] windows: interval=5m0s ` +
		`Error: enterprise windows enumerate: load config: config: managed standalone guardrail.custom_packs.acme.path C:\packs\acme: ` +
		`the gateway service account ` + account + ` cannot list or read the permissions of the parent folder C:\packs; grant it Read & execute on that folder`
	if _, code, ok := windowsEnterpriseEnumeratorFailureText(enumerator); !ok || code != "rule_pack_unreadable" {
		t.Fatalf("enumerator parent folder: ok=%t code=%q", ok, code)
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

// GAP-0920, GAP-1041: a LocalSystem run whose recovery failed is not told to
// run the same LocalSystem Setup command again, nor to correct a path and an
// account the error may not name; it gets the FORCE=1 last resort.
func TestWindowsEnterpriseStandaloneNextStepAfterALocalSystemRecovery(t *testing.T) {
	original := windowsEnterpriseRunningAsLocalSystem
	t.Cleanup(func() { windowsEnterpriseRunningAsLocalSystem = original })
	windowsEnterpriseRunningAsLocalSystem = func() bool { return true }
	got := windowsEnterpriseStandaloneNextStep("ensure", `C:\stage\config.yaml`, false, false, false, true, nil, nil, nil)
	if strings.Contains(got, "Next step: run DefenseClaw Setup") || !strings.Contains(got, "running it again unchanged fails the same way") ||
		!strings.Contains(got, `/ensure CONFIG=C:\stage\config.yaml JSON=1`) || strings.Contains(got, "(the path and the account)") ||
		!strings.Contains(got, "/uninstall FORCE=1 JSON=1") || !strings.HasSuffix(got, windowsEnterpriseSetupSourceNote) {
		t.Fatalf("next step = %q", got)
	}
	windowsEnterpriseRunningAsLocalSystem = func() bool { return false }
	if got := windowsEnterpriseStandaloneNextStep("ensure", `C:\stage\config.yaml`, false, false, false, true, nil, nil, nil); !strings.Contains(got, "Next step: run DefenseClaw Setup") {
		t.Fatalf("an administrator run lost the LocalSystem step: %q", got)
	}
}

// GAP-0622: a run refused lifecycle_busy recovered nothing; the pending
// transaction is the lock holder's. It is told to wait and run again, not
// the FORCE=1 last resort that would remove a deployment an upgrade is
// still changing, for every action and whoever ran it.
func TestWindowsEnterpriseStandaloneNextStepWhileAnotherLifecycleHoldsTheLock(t *testing.T) {
	original := windowsEnterpriseRunningAsLocalSystem
	t.Cleanup(func() { windowsEnterpriseRunningAsLocalSystem = original })
	for _, system := range []bool{true, false} {
		windowsEnterpriseRunningAsLocalSystem = func() bool { return system }
		for _, action := range []string{"ensure", "repair", "uninstall"} {
			for _, pending := range []bool{true, false} {
				got := windowsEnterpriseStandaloneNextStep(action, `C:\stage\config.yaml`, false, true, false, pending, nil, nil, nil)
				lower := strings.ToLower(got)
				if strings.Contains(got, "FORCE=1") || !strings.Contains(lower, "wait") ||
					!strings.Contains(got, windowsEnterpriseStandaloneSetupCommand(action, `C:\stage\config.yaml`, false)) {
					t.Fatalf("system=%v %s pending=%v: next step = %q", system, action, pending, got)
				}
			}
		}
	}
}

// GAP-0848: a FORCE=1 uninstall that failed printed the LocalSystem step,
// whose "otherwise, or if it fails the same way" was the same FORCE=1 command
// that had just failed. A failed forced uninstall names what stops it (a
// program holding a DefenseClaw file), FORCE=1 again after that, and a
// restart of Windows as the way out when no program can be named or ended;
// never a plain /uninstall, which a pending transaction refuses.
func TestWindowsEnterpriseStandaloneNextStepAfterAFailedForcedUninstall(t *testing.T) {
	original := windowsEnterpriseRunningAsLocalSystem
	t.Cleanup(func() { windowsEnterpriseRunningAsLocalSystem = original })
	for _, localSystem := range []bool{true, false} {
		windowsEnterpriseRunningAsLocalSystem = func() bool { return localSystem }
		for _, refusal := range []*windowsEnterpriseRecoveryGatewayRefusal{nil, {Code: "same_binary"}} {
			got := windowsEnterpriseStandaloneNextStep("uninstall", "", false, false, true, true, nil, refusal, nil)
			for _, want := range []string{
				"The forced uninstall did not finish.",
				"holds a DefenseClaw file",
				"then run " + windowsEnterpriseSetupCommand("/uninstall", "FORCE=1", "JSON=1") + " again as LocalSystem",
				"restart Windows and run " + windowsEnterpriseSetupCommand("/uninstall", "FORCE=1", "JSON=1") + " as LocalSystem",
				managed.WindowsSetupSource,
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("localSystem=%t refusal=%v: next step %q does not say %q", localSystem, refusal, got, want)
				}
			}
			for _, unwanted := range []string{"Otherwise, or if it fails the same way", "/uninstall JSON=1", "without recovering the transaction"} {
				if strings.Contains(got, unwanted) {
					t.Fatalf("localSystem=%t refusal=%v: next step %q says %q", localSystem, refusal, got, unwanted)
				}
			}
		}
	}
	// A plain uninstall keeps FORCE=1 as its last resort.
	windowsEnterpriseRunningAsLocalSystem = func() bool { return true }
	if got := windowsEnterpriseStandaloneNextStep("uninstall", "", false, false, false, true, nil, nil, nil); !strings.Contains(got, "/uninstall FORCE=1 JSON=1") ||
		strings.Contains(got, "The forced uninstall did not finish") {
		t.Fatalf("plain uninstall next step = %q", got)
	}
}

// GAP-0029: a pending transaction says the services stay stopped only for
// the ones that are stopped; a rollback that restarted every service said
// they all stayed stopped. It says they keep enforcing only when every
// standalone service is listed and running: a service the service manager
// does not have (absent, so not listed) counts as not running.
func TestWindowsEnterprisePendingLeadFollowsTheServiceStates(t *testing.T) {
	service := func(name, state string) enterprisestatus.Service {
		return enterprisestatus.Service{Name: name, State: state, Required: true}
	}
	roster := func(states map[string]string) []enterprisestatus.Service {
		var services []enterprisestatus.Service
		for _, name := range []string{"DefenseClawGateway", "DefenseClawHookGuardian", "DefenseClawHookEnumerator", "DefenseClawSensorHelper"} {
			if state, ok := states[name]; ok {
				services = append(services, service(name, state))
			}
		}
		return services
	}
	allRunning := map[string]string{"DefenseClawGateway": "running", "DefenseClawHookGuardian": "running",
		"DefenseClawHookEnumerator": "running", "DefenseClawSensorHelper": "running"}
	with := func(changes map[string]string) map[string]string {
		states := map[string]string{}
		for name, state := range allRunning {
			states[name] = state
		}
		for name, state := range changes {
			if state == "" {
				delete(states, name)
			} else {
				states[name] = state
			}
		}
		return states
	}
	const enforcing = "services are running and keep enforcing"
	const generic = "The transaction is still pending, so the deployment cannot be changed until it is recovered."
	for _, tc := range []struct {
		name     string
		services []enterprisestatus.Service
		want     string
	}{
		{"all running", roster(allRunning), enforcing},
		{"gateway absent, the rest running", roster(with(map[string]string{"DefenseClawGateway": ""})), generic},
		{"sensor helper absent, the rest running", roster(with(map[string]string{"DefenseClawSensorHelper": ""})), generic},
		{"only gateway and guardian listed", roster(map[string]string{"DefenseClawGateway": "running", "DefenseClawHookGuardian": "running"}), generic},
		{"gateway stopped", roster(with(map[string]string{"DefenseClawGateway": "stopped"})), "the DefenseClawGateway service stays stopped"},
		{"gateway absent, guardian stopped", roster(with(map[string]string{"DefenseClawGateway": "", "DefenseClawHookGuardian": "stopped"})), "the DefenseClawHookGuardian service stays stopped"},
		{"two stopped", roster(with(map[string]string{"DefenseClawGateway": "stopped", "DefenseClawHookGuardian": "stopped"})), "the DefenseClawGateway, DefenseClawHookGuardian services stay stopped"},
		{"none present", nil, generic},
		{"state unknown", roster(with(map[string]string{"DefenseClawGateway": "unknown"})), generic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsEnterprisePendingLead(tc.services)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("lead = %q, want %q", got, tc.want)
			}
			if tc.want != enforcing && strings.Contains(got, "keep enforcing") {
				t.Fatalf("lead = %q claims enforcement", got)
			}
			if tc.want == enforcing && strings.Contains(got, "stopped") {
				t.Fatalf("lead = %q names a stopped service", got)
			}
		})
	}
}

func TestWindowsEnterprisePendingInspectionDoesNotClaimRunningServicesStopped(t *testing.T) {
	step := windowsEnterprisePendingInspectionStep(`C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`)
	if strings.Contains(step, "services stay stopped") || !strings.Contains(step, "lifecycle transaction is pending") ||
		!strings.Contains(step, "Setup") {
		t.Fatalf("pending status guidance contradicts four running services: %q", step)
	}
}

// GAP-0741: a committed install whose lifecycle journal could not be retired
// because of a per-user .defenseclaw folder says it is installed, names the
// folder and its fix, and says that /ensure again converges.
func TestWindowsEnterpriseCommittedJournalNextStep(t *testing.T) {
	original := `Install committed, but its protected managed-hook lifecycle journal could not be retired: retire copilot managed runtime generations for SID S-1-5-21-1-2-3-1018: enterprise hooks: managed runtime generation directory is untrusted: C:\Users\dcw-std2\.defenseclaw\hooks: access denied`
	step := windowsEnterpriseCommittedJournalNextStep(original, true)
	for _, want := range []string{"installed and running", `C:\Users\dcw-std2\.defenseclaw was left by a per-user`, "uninstall --all --binaries --yes", "run " + windowsEnterpriseAdminCommand("ensure") + " from an elevated PowerShell prompt again"} {
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

// A failed lifecycle never hands the administrator security-descriptor
// internals (ACE counts, DACL shapes, SDDL): a known diagnostic becomes a plain
// statement about its path, an unknown one keeps its context and names the
// path, and a message without such detail is kept as it is.
func TestWindowsEnterpriseStandaloneErrorTextHidesSecurityDescriptorDetail(t *testing.T) {
	for _, test := range []struct {
		message, want string
		internal      bool
	}{
		{
			message:  `enterprise hooks: managed Windows DACL on C:\ProgramData\DefenseClaw has 8 ACEs, expected 7`,
			want:     `enterprise hooks: the permissions on C:\ProgramData\DefenseClaw are not the ones DefenseClaw set`,
			internal: true,
		},
		{
			message:  `read DACL of C:\Users\u1\.defenseclaw: Access is denied.`,
			want:     `DefenseClaw could not read the permissions on C:\Users\u1\.defenseclaw (Access is denied.)`,
			internal: true,
		},
		{
			message:  `apply managed state: set SDDL O:BAG:SY on C:\ProgramData\DefenseClaw\hooks: access denied`,
			want:     `apply managed state: DefenseClaw could not verify or apply the permissions on C:\ProgramData\DefenseClaw\hooks`,
			internal: true,
		},
		{
			message:  `ACL mismatch`,
			want:     `DefenseClaw could not verify or apply the permissions of a managed path`,
			internal: true,
		},
		{message: "  the gateway did not start  ", want: "the gateway did not start"},
		// A file name that holds the word is not detail: the refusal keeps
		// its path and the exact icacls fix (GAP-0602).
		{
			message: `C:\ProgramData\Cisco\DefenseClaw\install\codex-requirements-acl-backup.json is owned by BUILTIN\Users (S-1-5-32-545), not an administrator. Fix: icacls "C:\ProgramData\Cisco\DefenseClaw\install\codex-requirements-acl-backup.json" /setowner *S-1-5-32-544`,
			want:    `C:\ProgramData\Cisco\DefenseClaw\install\codex-requirements-acl-backup.json is owned by BUILTIN\Users (S-1-5-32-545), not an administrator. Fix: icacls "C:\ProgramData\Cisco\DefenseClaw\install\codex-requirements-acl-backup.json" /setowner *S-1-5-32-544`,
		},
	} {
		got, internal := windowsEnterpriseStandaloneErrorText(test.message)
		if got != test.want || internal != test.internal {
			t.Errorf("windowsEnterpriseStandaloneErrorText(%q) = %q, %v; want %q, %v", test.message, got, internal, test.want, test.internal)
		}
	}
}

// GAP-0803: a rollback a program holding a Codex file stopped is not told that
// running it again "fails the same way" or to force the uninstall: the error
// says to close the program, and the same command then finishes the rollback.
func TestWindowsEnterpriseHeldRollbackNextStepNamesOnlyThePendingTransaction(t *testing.T) {
	original := windowsEnterpriseRunningAsLocalSystem
	t.Cleanup(func() { windowsEnterpriseRunningAsLocalSystem = original })
	windowsEnterpriseRunningAsLocalSystem = func() bool { return true }
	if got := windowsEnterpriseHeldRollbackNextStep(false, nil); got != "" {
		t.Fatalf("without a pending transaction: %q", got)
	}
	got := windowsEnterpriseHeldRollbackNextStep(true, nil)
	if !strings.Contains(got, "transaction is still pending") || strings.Contains(got, "fails the same way") || strings.Contains(got, "FORCE=1") {
		t.Fatalf("held rollback next step = %q", got)
	}
}

// GAP-0999: the next step of a rollback a Codex writer left pending never says the
// services keep enforcing, and still names a stopped service.
func TestWindowsEnterprisePendingUnsettledLeadNeverSaysEnforcing(t *testing.T) {
	var services []enterprisestatus.Service
	for _, name := range []string{"DefenseClawGateway", "DefenseClawHookGuardian", "DefenseClawHookEnumerator", "DefenseClawSensorHelper"} {
		services = append(services, enterprisestatus.Service{Name: name, State: "running", Required: true})
	}
	got := windowsEnterprisePendingUnsettledLead(services)
	if strings.Contains(got, "enforcing") || !strings.Contains(got, "protection may be incomplete") || !strings.Contains(got, "verify says what is not covered") {
		t.Fatalf("unsettled lead with running services = %q", got)
	}
	services[0].State = "stopped"
	got = windowsEnterprisePendingUnsettledLead(services)
	if !strings.Contains(got, "DefenseClawGateway service stays stopped") || strings.Contains(got, "enforcing") {
		t.Fatalf("unsettled lead with a stopped service = %q", got)
	}
}

// GAP-0947: a rollback a late holder stopped starts the restored services and
// ends with the held code; the next step says they keep enforcing and never
// offers the forced uninstall.
func TestWindowsEnterpriseHeldRollbackNextStepWithRunningServicesKeepsEnforcingAndNeverForces(t *testing.T) {
	var services []enterprisestatus.Service
	for _, name := range []string{"DefenseClawGateway", "DefenseClawHookGuardian", "DefenseClawHookEnumerator", "DefenseClawSensorHelper"} {
		services = append(services, enterprisestatus.Service{Name: name, State: "running", Required: true})
	}
	got := windowsEnterpriseHeldRollbackNextStep(true, services)
	if !strings.Contains(got, "keep enforcing") || strings.Contains(got, "stay stopped") || strings.Contains(got, "FORCE=1") || strings.Contains(got, "fails the same way") {
		t.Fatalf("held rollback next step with running services = %q", got)
	}
	services[0].State = "stopped"
	got = windowsEnterpriseHeldRollbackNextStep(true, services)
	if !strings.Contains(got, "DefenseClawGateway service stays stopped") || strings.Contains(got, "FORCE=1") {
		t.Fatalf("held rollback next step with a stopped service = %q", got)
	}
}
