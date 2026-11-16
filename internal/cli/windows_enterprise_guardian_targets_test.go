// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0146: a target that waits for its signed-out account, or whose hook
// file is gone, is not security-complete in status or verify.
func TestWindowsEnterpriseGuardianTargetGapsClearSecurityComplete(t *testing.T) {
	home := t.TempDir()
	hookFile := filepath.Join(home, ".copilot", "hooks", "defenseclaw-vscode.json")
	if err := os.MkdirAll(filepath.Dir(hookFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(home, ".copilot", "config.json")
	if err := os.WriteFile(configFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verified := enterpriseHookReconcileRow{
		User: "dcw-std1", UserHome: home, SID: "S-1-5-21-1-2-3-1017", Connector: "copilot", OK: true,
		Result: &enterprisehooks.InstallResult{Connector: "copilot", HookConfigPaths: []string{configFile}},
	}
	files := func(row enterpriseHookReconcileRow) []string {
		return windowsEnterpriseGuardianRowHookFiles(row, []string{hookFile})
	}
	run := func(rows ...enterpriseHookReconcileRow) *enterprisestatus.Result {
		result := &enterprisestatus.Result{Action: "status", SecurityComplete: true}
		applyWindowsEnterpriseGuardianTargetGaps(result, enterpriseHookGuardianState{Results: rows}, files)
		return result
	}

	if result := run(verified, enterpriseHookReconcileRow{User: "dcw-std2", Connector: "copilot", Pending: true}); !result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("verified and pending rows with their files: security_complete=%t warnings=%+v, want complete and none", result.SecurityComplete, result.Warnings)
	}

	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	result := run(verified)
	if result.SecurityComplete || len(result.Warnings) != 1 ||
		result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
		!strings.Contains(result.Warnings[0].Message, hookFile) ||
		!strings.Contains(result.Warnings[0].Message, "dcw-std1 for copilot") {
		t.Fatalf("deleted hook file: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending naming the file", result.SecurityComplete, result.Warnings)
	}

	waiting := enterpriseHookReconcileRow{
		User: "dcw-std1", UserHome: home, SID: verified.SID, Connector: "copilot",
		Error: enterpriseHookAwaitingSignInPrefix + ": DefenseClaw 1.0.2 protected it (verification: hook file missing)",
	}
	result = run(waiting)
	if result.SecurityComplete || len(result.Warnings) != 1 ||
		result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
		!strings.Contains(result.Warnings[0].Message, "copilot for dcw-std1") {
		t.Fatalf("row waiting for sign-in: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending", result.SecurityComplete, result.Warnings)
	}

	failed := waiting
	failed.Error = "enterprise hooks: target install failed: access is denied"
	result = run(failed)
	if result.SecurityComplete || len(result.Warnings) != 1 ||
		result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
		!strings.Contains(result.Warnings[0].Message, hookFile) ||
		!strings.Contains(result.Warnings[0].Message, "dcw-std1 for copilot") {
		t.Fatalf("failed row with its hook file deleted: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending naming the file",
			result.SecurityComplete, result.Warnings)
	}
}

// GAP-0146 (train T2, BW-02 step 4): the guardian could not repair a
// deleted Copilot hook file of an account with no active Windows session.
// Status and verify gave only the guardian's lifecycle error, without the
// guardian_repair_pending warning that names the account and the agent.
// Signed out, disconnected and connected accounts are covered.
func TestWindowsEnterpriseGuardianTargetGapsNameTargetsTheGuardianCannotRepair(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = nil // the enterprise windows commands skip the config load

	home := t.TempDir()
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	if err := os.MkdirAll(filepath.Dir(hookFile), 0o700); err != nil {
		t.Fatal(err)
	}
	const sid = "S-1-5-21-1-2-3-1017"
	row := func(ok bool, rowErr string) enterpriseHookReconcileRow {
		return enterpriseHookReconcileRow{
			User: `WIN-HOST\dcw-std1`, UserHome: home, SID: sid, Connector: "copilot", OK: ok, Error: rowErr,
		}
	}
	signedOut := row(false, "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable "+
		"(verification: enterprise hooks: copilot VS Code Local hooks: DefenseClaw's VS Code Local hooks are not current: "+hookFile+")")
	disconnected := row(false, (&enterprisehooks.WindowsTargetSessionUnavailableError{SID: sid}).Error())
	connected := row(true, "")
	files := windowsEnterpriseGuardianTargetHookFiles(true)
	run := func(action string, r enterpriseHookReconcileRow) *enterprisestatus.Result {
		result := &enterprisestatus.Result{Action: action, SecurityComplete: true}
		applyWindowsEnterpriseGuardianTargetGaps(result, enterpriseHookGuardianState{Results: []enterpriseHookReconcileRow{r}}, files)
		return result
	}
	pending := func(name string, result *enterprisestatus.Result, wants ...string) {
		t.Helper()
		if result.SecurityComplete || len(result.Warnings) != 1 || result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode {
			t.Fatalf("%s: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending",
				name, result.SecurityComplete, result.Warnings)
		}
		for _, want := range wants {
			if !strings.Contains(result.Warnings[0].Message, want) {
				t.Fatalf("%s: warning %q does not name %q", name, result.Warnings[0].Message, want)
			}
		}
	}

	for _, action := range []string{"status", "verify"} {
		// Hook file absent.
		pending(action+": signed out, hook file deleted", run(action, signedOut),
			"copilot for "+signedOut.User, "signed out", hookFile)
		pending(action+": disconnected, hook file deleted", run(action, disconnected),
			"copilot for "+disconnected.User, "disconnected", hookFile)
		pending(action+": connected, hook file deleted since the pass", run(action, connected),
			signedOut.User+" for copilot", hookFile)
	}

	if err := os.WriteFile(hookFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Hook file present: an account the guardian cannot reach is still not
	// verified; a connected, verified one is complete again.
	pending("signed out, hook file present", run("status", signedOut), "copilot for "+signedOut.User)
	pending("disconnected, hook file present", run("verify", disconnected), "copilot for "+disconnected.User)
	if result := run("status", connected); !result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("connected, hook file restored: security_complete=%t warnings=%+v, want complete and none",
			result.SecurityComplete, result.Warnings)
	}
	if msg := run("status", signedOut).Warnings[0].Message; strings.Contains(msg, "missing") {
		t.Fatalf("signed out, hook file present: warning %q names a missing file", msg)
	}
}

func TestWindowsEnterpriseGuardianRowHookFilesListsEachFileOnce(t *testing.T) {
	a, b, c := filepath.FromSlash("/a/hooks.json"), filepath.FromSlash("/b/config.json"), filepath.FromSlash("/c/extra.json")
	row := enterpriseHookReconcileRow{Result: &enterprisehooks.InstallResult{HookConfigPaths: []string{b, a, " "}}}
	got := windowsEnterpriseGuardianRowHookFiles(row, []string{a, c})
	want := []string{a, b, c}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v", got, want)
	}
	if got := windowsEnterpriseGuardianRowHookFiles(enterpriseHookReconcileRow{}, nil); len(got) != 0 {
		t.Fatalf("row without a result: files = %v, want none", got)
	}
}

// GAP-0146 (group test on ea2f749fca): status and verify run without a
// loaded config, so the check of a verified Copilot target never listed its
// VS Code Local hook file and a deleted one left status security-complete.
// The file is now decided from the installed config.
func TestWindowsEnterpriseGuardianTargetsStatusProcessChecksTheCopilotVSCodeHookFile(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = nil // the enterprise windows commands skip the config load

	home := t.TempDir()
	configFile := filepath.Join(home, ".copilot", "config.json")
	if err := os.MkdirAll(filepath.Dir(configFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	state := enterpriseHookGuardianState{Results: []enterpriseHookReconcileRow{{
		User: "dcw-std1", UserHome: home, SID: "S-1-5-21-1-2-3-1017", Connector: "copilot", OK: true,
		Result: &enterprisehooks.InstallResult{Connector: "copilot", HookConfigPaths: []string{configFile}},
	}}}
	loadState := func() (enterpriseHookGuardianState, bool, error) { return state, true, nil }
	installed := func(localHarness string) func() (*config.Config, error) {
		return func() (*config.Config, error) {
			return &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise: config.EnterpriseConfig{
					Profile: managed.ProfileStandalone,
					MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
						"copilot": {LocalHarness: localHarness},
					}},
				},
			}, nil
		}
	}
	run := func(loadInstalled func() (*config.Config, error)) *enterprisestatus.Result {
		result := &enterprisestatus.Result{Action: "status", SecurityComplete: true}
		applyWindowsEnterpriseGuardianTargetsFrom(result, loadState, loadInstalled)
		return result
	}
	missing := func(name string, result *enterprisestatus.Result) {
		t.Helper()
		if result.SecurityComplete || len(result.Warnings) != 1 ||
			result.Warnings[0].Code != windowsEnterpriseGuardianRepairPendingCode ||
			!strings.Contains(result.Warnings[0].Message, hookFile) ||
			!strings.Contains(result.Warnings[0].Message, "dcw-std1 for copilot") {
			t.Fatalf("%s: security_complete=%t warnings=%+v, want incomplete with one guardian_repair_pending naming %s",
				name, result.SecurityComplete, result.Warnings, hookFile)
		}
	}

	missing("governed Copilot, VS Code hook file deleted", run(installed("")))
	missing("installed config unreadable (fail closed)", run(func() (*config.Config, error) { return nil, os.ErrPermission }))
	if result := run(installed(config.CopilotLocalHarnessRetire)); !result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("Local harness retired (no VS Code hook file is written): security_complete=%t warnings=%+v, want complete and none",
			result.SecurityComplete, result.Warnings)
	}

	if err := os.MkdirAll(filepath.Dir(hookFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := run(installed("")); !result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("VS Code hook file put back: security_complete=%t warnings=%+v, want complete and none", result.SecurityComplete, result.Warnings)
	}
	result := &enterprisestatus.Result{Action: "verify", SecurityComplete: true}
	applyWindowsEnterpriseGuardianTargetsFrom(result, func() (enterpriseHookGuardianState, bool, error) {
		return enterpriseHookGuardianState{}, false, nil
	}, installed(""))
	if !result.SecurityComplete || len(result.Warnings) != 0 {
		t.Fatalf("no guardian state: security_complete=%t warnings=%+v, want it left to the guardian status", result.SecurityComplete, result.Warnings)
	}
}
