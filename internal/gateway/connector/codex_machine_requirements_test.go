// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestWindowsCodexMachinePrerequisitesDecoupleClaudeEffectivePolicy(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.EnterpriseTargetEnabled = true
	opts.AgentApplicationControlEnforced = true
	opts.ClaudeTargetEnabled = true
	opts.ClaudeEffectivePolicyVerified = false
	opts.CodexTargetEnabled = true

	if err := validateWindowsCodexMachinePrerequisites(opts); err != nil {
		t.Fatalf("mixed two-phase prerequisites unexpectedly failed: %v", err)
	}
	if windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("aggregate security_complete must remain false until Claude live proof succeeds")
	}

	opts.AgentApplicationControlEnforced = false
	if err := validateWindowsCodexMachinePrerequisites(opts); err != nil {
		t.Fatalf("optional application-control posture unexpectedly failed: %v", err)
	}
}

func TestWindowsCodexMachineSecurityCompleteRequiresEnabledTarget(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.AgentApplicationControlEnforced = true
	if windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("zero-target deployment must not report security_complete")
	}

	opts.EnterpriseTargetEnabled = true
	opts.ClaudeTargetEnabled = true
	opts.ClaudeEffectivePolicyVerified = true
	if !windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("verified Claude-only target should be security-complete")
	}

	opts.ClaudeTargetEnabled = false
	opts.ClaudeEffectivePolicyVerified = false
	opts.CodexTargetEnabled = true
	opts.AgentApplicationControlEnforced = false
	if !windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("Codex-only target should be security-complete without optional application control")
	}

	opts.CodexTargetEnabled = false
	opts.CursorTargetEnabled = true
	if !windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("Cursor-only target should be security-complete without optional application control")
	}
	// Regression guard: Cursor plumbing must reach the emitted report so
	// a future refactor that drops CursorTargetEnabled from
	// windowsCodexMachineReport fails this test rather than silently
	// misclassifying Cursor targets.
	if report := windowsCodexMachineReport("inspect", opts); !report.CursorTargetEnabled ||
		report.CodexTargetEnabled || report.ClaudeTargetEnabled {
		t.Fatalf("Cursor target flag did not reach the report: %+v", report)
	}

	opts.EnterpriseTargetEnabled = false
	if windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("disabled last target must clear security_complete")
	}
}

func TestNormalizeWindowsManagedGatewayAddrRequiresExactCanonicalIPv4Loopback(t *testing.T) {
	for _, value := range []string{
		"",
		"localhost:18970",
		"[::1]:18970",
		"[::ffff:127.0.0.1]:18970",
		"127.0.0.2:18970",
		"127.1.2.3:18970",
		"127.0.0.1:018970",
		" 127.0.0.1:18970",
		"127.0.0.1:18970 ",
		"0.0.0.0:18970",
	} {
		if _, err := NormalizeWindowsManagedGatewayAddr(value); err == nil {
			t.Fatalf("NormalizeWindowsManagedGatewayAddr(%q) unexpectedly succeeded", value)
		}
	}
	if got, err := NormalizeWindowsManagedGatewayAddr("127.0.0.1:18970"); err != nil ||
		got != "127.0.0.1:18970" {
		t.Fatalf("canonical managed gateway = %q, %v", got, err)
	}
}

func testWindowsCodexMachineOptions() WindowsCodexMachineRequirementsOptions {
	return WindowsCodexMachineRequirementsOptions{
		RequirementsPath: `C:\ProgramData\OpenAI\Codex\requirements.toml`,
		ManagedDir:       `C:\Program Files\DefenseClaw\bin`,
		HookBinary:       `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		OwnershipPath:    `C:\ProgramData\DefenseClaw\state\install\codex-requirements-ownership.json`,
		ManagedStatePath: `C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-hooks.state`,
	}
}

func TestRemoveWindowsCodexRequirementsOwnedChangesPreservesSharedControls(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	baseline := []byte("administrator_key = \"preserve\"\n")
	managed, _, err := reconcileWindowsCodexRequirements(baseline, opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWindowsCodexRequirements(managed)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	event := codexHookGroups[0].eventType
	groups := hooks[event].([]interface{})
	groups = append(groups, map[string]interface{}{
		"matcher": "administrator-owned",
		"hooks": []interface{}{map[string]interface{}{
			"type":            "command",
			"command":         `C:\AdministratorHooks\audit.exe`,
			"command_windows": `C:\AdministratorHooks\audit.exe`,
			"timeout":         int64(9),
		}},
	})
	hooks[event] = groups
	cfg["hooks"] = hooks
	withLaterAdminHook, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cleaned, changed, err := removeWindowsCodexRequirementsOwnedChanges(
		withLaterAdminHook,
		baseline,
		opts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected DefenseClaw groups to be removed")
	}
	cleanedCfg, err := parseWindowsCodexRequirements(cleaned)
	if err != nil {
		t.Fatal(err)
	}
	if managedOnly, ok := cleanedCfg["allow_managed_hooks_only"].(bool); !ok || !managedOnly {
		t.Fatalf("shared allow_managed_hooks_only was not preserved: %#v", cleanedCfg)
	}
	features := cleanedCfg["features"].(map[string]interface{})
	if enabled, ok := features["hooks"].(bool); !ok || !enabled {
		t.Fatalf("shared features.hooks was not preserved: %#v", features)
	}
	cleanedHooks := cleanedCfg["hooks"].(map[string]interface{})
	if got := cleanedHooks["windows_managed_dir"]; got != opts.ManagedDir {
		t.Fatalf("shared managed directory = %#v, want %q", got, opts.ManagedDir)
	}
	cleanedGroups := cleanedHooks[event].([]interface{})
	if len(cleanedGroups) != 1 {
		t.Fatalf("remaining administrator groups = %d, want 1", len(cleanedGroups))
	}
	references, err := windowsCodexOwnedPathReferenceCount(cleaned, opts)
	if err != nil {
		t.Fatal(err)
	}
	if references == 0 {
		t.Fatal("surviving managed directory must keep binary removal unsafe")
	}
}

func TestRemoveWindowsCodexRequirementsOwnedChangesDropsUnsharedControls(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	baseline := []byte("administrator_key = \"preserve\"\n")
	managed, _, err := reconcileWindowsCodexRequirements(baseline, opts)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, changed, err := removeWindowsCodexRequirementsOwnedChanges(managed, baseline, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected managed requirements to change")
	}
	cfg, err := parseWindowsCodexRequirements(cleaned)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := cfg["allow_managed_hooks_only"]; present {
		t.Fatalf("unowned allow_managed_hooks_only survived: %#v", cfg)
	}
	if _, present := cfg["features"]; present {
		t.Fatalf("unowned features table survived: %#v", cfg)
	}
	if _, present := cfg["hooks"]; present {
		t.Fatalf("unowned hooks table survived: %#v", cfg)
	}
	if cfg["administrator_key"] != "preserve" {
		t.Fatalf("administrator key was not preserved: %#v", cfg)
	}
	references, err := windowsCodexOwnedPathReferenceCount(cleaned, opts)
	if err != nil {
		t.Fatal(err)
	}
	if references != 0 {
		t.Fatalf("owned path references = %d, want 0", references)
	}
}

func TestWindowsCodexOwnedPathReferenceCountFindsSurvivingCommand(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	raw := []byte(`
[hooks]
windows_managed_dir = 'C:\AdministratorHooks'

[[hooks.SessionStart]]
matcher = "admin"

[[hooks.SessionStart.hooks]]
type = "command"
command = '"C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe" hook'
command_windows = '"C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe" hook'
timeout = 5
`)
	references, err := windowsCodexOwnedPathReferenceCount(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	if references != 2 {
		t.Fatalf("owned path references = %d, want 2", references)
	}
}

// Each managed group runs the hook with its own event and the machine hook
// contract through Start-Process -Wait. The hook refuses a Codex invocation
// without both, and the PowerShell call operator does not wait for the
// GUI-subsystem launcher, so the earlier command's exit code never reached
// Codex.
func TestWindowsCodexManagedHookCommandBindsEventAndContract(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	contractID := windowsCodexMachineHookContract()
	if want := resolveHookContractForOS("codex", "", "windows").Contract.ContractID; contractID == "" || contractID != want {
		t.Fatalf("machine hook contract = %q, want the Codex default %q", contractID, want)
	}
	contract, ok := hookContractByID("codex", contractID)
	if !ok {
		t.Fatalf("machine hook contract %q is not registered", contractID)
	}
	registered := map[string]bool{}
	for _, event := range contract.Events {
		registered[event] = true
	}
	prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	commands := map[string]string{}
	for _, group := range codexHookGroups {
		if !registered[group.eventType] {
			t.Errorf("machine hook contract %s does not register %s", contractID, group.eventType)
		}
		command := windowsCodexManagedHookCommand(opts.HookBinary, group.eventType)
		if !strings.HasPrefix(command, prefix) {
			t.Fatalf("%s command %q does not use the fixed system PowerShell", group.eventType, command)
		}
		want := "$ErrorActionPreference='Stop'; $env:NoDefaultCurrentDirectoryInExePath='1'; " +
			"if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { $ErrorActionPreference='Continue'; & " +
			powershellQuoteLiteral(opts.HookBinary) +
			" 'hook' '--connector' 'codex' '--enterprise-managed' '--event' '" + group.eventType +
			"' '--hook-contract' '" + contractID + "' | Microsoft.PowerShell.Core\\Out-Host; exit $LASTEXITCODE }; " +
			"$hookStart=[System.Diagnostics.ProcessStartInfo]::new(" + powershellQuoteLiteral(opts.HookBinary) +
			",'hook --connector codex --enterprise-managed --event " + group.eventType +
			" --hook-contract " + contractID + "'); $hookStart.UseShellExecute=$false; " +
			"$hookProcess=[System.Diagnostics.Process]::Start($hookStart); $hookProcess.WaitForExit(); exit $hookProcess.ExitCode"
		if got := decodePowerShellEncodedCommandForTest(t, command); got != want {
			t.Fatalf("%s script\n got: %s\nwant: %s", group.eventType, got, want)
		}
		if previous, seen := commands[command]; seen {
			t.Fatalf("%s and %s share one command", previous, group.eventType)
		}
		commands[command] = group.eventType
	}

	legacy := decodePowerShellEncodedCommandForTest(t, windowsCodexLegacyManagedHookCommand(opts.HookBinary))
	if legacy != "$ErrorActionPreference='Stop'; $env:NoDefaultCurrentDirectoryInExePath='1'; & "+
		powershellQuoteLiteral(opts.HookBinary)+" hook --connector codex --enterprise-managed; exit $LASTEXITCODE" {
		t.Fatalf("legacy command no longer matches what earlier releases published: %s", legacy)
	}
	if _, bound := commands[windowsCodexLegacyManagedHookCommand(opts.HookBinary)]; bound {
		t.Fatal("the legacy command is still a managed group command")
	}
}
