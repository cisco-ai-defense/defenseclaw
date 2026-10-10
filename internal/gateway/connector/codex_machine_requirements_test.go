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
	// GAP-0238: rows without a Windows machine policy do not count, as in the
	// installer module; they made status and verify throw instead.
	for _, name := range []string{"copilot", "opencode", "hermes"} {
		opts.EnableManifestTarget(name)
	}
	if windowsCodexMachineSecurityComplete(opts) {
		t.Fatal("a deployment without a Codex, Claude Code or Cursor row must not report security_complete")
	}

	opts.EnableManifestTarget("ClaudeCode")
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

	opts.CursorTargetEnabled = false
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

// GAP-1025: an upgrade from 1.0.0 added the current DefenseClaw group next
// to the 1.0.0 one (its Start-Process command) in every event, so every
// Codex hook ran twice. Reconcile replaces DefenseClaw's own groups of any
// release by their marker and keeps the administrator's.
func TestReconcileWindowsCodexRequirementsReplacesTheOneZeroHookSet(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = KnownHookContracts("codex")[0].ContractID
	// The 1.0.0 (d48efaa18) form of the bound managed command.
	oneZero := func(event string) string {
		quoted := []string{}
		for _, argument := range []string{"hook", "--connector", "codex", "--enterprise-managed", "--event", event, "--hook-contract", opts.HookContractID} {
			quoted = append(quoted, powershellQuoteLiteral(argument))
		}
		script := strings.Join([]string{
			"$ErrorActionPreference='Stop'",
			"$env:NoDefaultCurrentDirectoryInExePath='1'",
			"$hookProcess=Microsoft.PowerShell.Management\\Start-Process -FilePath " + powershellQuoteLiteral(opts.HookBinary) +
				" -ArgumentList @(" + strings.Join(quoted, ",") + ") -NoNewWindow -Wait -PassThru",
			"exit $hookProcess.ExitCode",
		}, "; ")
		return windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
	}
	old := windowsCodexMachineLayout(opts)
	old.owned = nil
	old.handler = func(group codexHookGroup) map[string]interface{} {
		return windowsCodexMachineHandler(oneZero(group.eventType), group.timeout)
	}
	admin := map[string]interface{}{"matcher": "admin", "hooks": []interface{}{
		map[string]interface{}{"type": "command", "command": "audit.exe", "timeout": int64(5)},
	}}
	cfg := map[string]interface{}{
		"administrator_key": "preserve",
		"hooks":             map[string]interface{}{"SessionStart": []interface{}{admin}},
	}
	if err := old.reconcile(cfg); err != nil {
		t.Fatal(err)
	}
	upgraded, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := reconcileWindowsCodexRequirements(upgraded, opts)
	if err != nil || !changed {
		t.Fatalf("reconcile of the 1.0.0 form: changed=%v err=%v", changed, err)
	}
	got, err := parseWindowsCodexRequirements(rendered)
	if err != nil {
		t.Fatal(err)
	}
	hooks := got["hooks"].(map[string]interface{})
	commands := 0
	for _, expected := range codexHookGroups {
		groups, _ := hooks[expected.eventType].([]interface{})
		want := 1
		if expected.eventType == "SessionStart" {
			want = 2 // the administrator's group stays
		}
		if len(groups) != want {
			t.Fatalf("hooks.%s has %d groups, want %d", expected.eventType, len(groups), want)
		}
		for _, group := range groups {
			if windowsCodexOwnedHookGroup(group, opts.HookBinary) {
				commands++
			}
		}
	}
	if commands != len(codexHookGroups) || got["administrator_key"] != "preserve" {
		t.Fatalf("DefenseClaw commands = %d, want %d; administrator key = %v", commands, len(codexHookGroups), got["administrator_key"])
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

// GAP-0938: a standalone ensure adopts requirements a purged deployment
// left with its exact hooks: the preimage is the file without DefenseClaw's
// changes (nothing, when DefenseClaw created it). Secure Client refuses.
func TestAdoptWindowsCodexOrphanedRequirements(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = "test-contract"
	created, _, err := reconcileWindowsCodexRequirements(nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if preimage, existed, err := adoptWindowsCodexOrphanedRequirements(created, opts); err != nil || existed || len(preimage) != 0 {
		t.Fatalf("created by DefenseClaw: %q, %t, %v", preimage, existed, err)
	}
	merged, _, err := reconcileWindowsCodexRequirements([]byte("administrator_key = \"preserve\"\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	preimage, existed, err := adoptWindowsCodexOrphanedRequirements(merged, opts)
	if err != nil || !existed {
		t.Fatalf("merged: %t, %v", existed, err)
	}
	cfg, err := parseWindowsCodexRequirements(preimage)
	if err != nil || cfg["administrator_key"] != "preserve" || cfg["hooks"] != nil {
		t.Fatalf("adopted preimage %q (%v)", preimage, err)
	}
	opts.HookContractID = ""
	if _, _, err := adoptWindowsCodexOrphanedRequirements(merged, opts); err == nil {
		t.Fatal("Secure Client adopted unowned DefenseClaw hooks")
	}
}
