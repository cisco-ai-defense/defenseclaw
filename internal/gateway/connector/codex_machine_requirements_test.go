// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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
			if windowsCodexOwnedHookGroup(group, expected.eventType, opts.HookBinary) {
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

func testWindowsCodexDiscardedOwnership(
	t *testing.T,
	layout WindowsCodexMachineRequirementsOptions,
	preimage []byte,
) *windowsCodexMachineOwnership {
	t.Helper()
	return &windowsCodexMachineOwnership{
		SchemaVersion:    windowsCodexMachineRequirementsSchema,
		RequirementsPath: layout.RequirementsPath,
		ManagedDir:       layout.ManagedDir,
		HookBinary:       layout.HookBinary,
		PreimageExisted:  len(preimage) != 0,
		Preimage:         append([]byte(nil), preimage...),
		PreimageSHA256:   windowsCodexMachineHash(preimage),
	}
}

func testWindowsCodexScopedLayout() WindowsCodexMachineRequirementsOptions {
	scoped := testWindowsCodexMachineOptions()
	scoped.ManagedDir = `C:\DefenseClawCert\run-17\bin`
	scoped.HookBinary = `C:\DefenseClawCert\run-17\bin\defenseclaw-hook.exe`
	return scoped
}

func mustParseWindowsCodexRequirements(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	cfg, err := parseWindowsCodexRequirements(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return cfg
}

// Identity-drift adoption (a prior scoped install's ownership record) must
// strip that install's hook groups and windows_managed_dir from both the live
// base and the recorded preimage, and must not record the isolation controls
// it wrote as administrator settings.
func TestWindowsCodexAdoptRequirementsStripsDiscardedLayout(t *testing.T) {
	for _, contract := range []string{"", KnownHookContracts("codex")[0].ContractID} {
		t.Run("contract="+contract, func(t *testing.T) {
			opts := testWindowsCodexMachineOptions()
			opts.HookContractID = contract
			scoped := testWindowsCodexScopedLayout()
			scoped.HookContractID = contract
			admin := []byte("administrator_key = \"preserve\"\n")
			stale, _, err := reconcileWindowsCodexRequirements(admin, scoped)
			if err != nil {
				t.Fatal(err)
			}
			adoption, err := windowsCodexAdoptRequirements(stale, true, testWindowsCodexDiscardedOwnership(t, scoped, admin), opts)
			if err != nil {
				t.Fatal(err)
			}
			if references, err := windowsCodexOwnedPathReferenceCount(adoption.base, scoped); err != nil || references != 0 {
				t.Fatalf("live base keeps %d prior-layout references (%v): %s", references, err, adoption.base)
			}
			if !adoption.preimageExisted {
				t.Fatal("administrator content was not recorded as a preimage")
			}
			cfg := mustParseWindowsCodexRequirements(t, adoption.preimage)
			if cfg["administrator_key"] != "preserve" || cfg["hooks"] != nil ||
				cfg["allow_managed_hooks_only"] != nil || cfg["features"] != nil {
				t.Fatalf("adopted preimage keeps DefenseClaw changes: %s", adoption.preimage)
			}
			rendered, _, err := reconcileWindowsCodexRequirements(adoption.base, opts)
			if err != nil {
				t.Fatal(err)
			}
			if references, err := windowsCodexOwnedPathReferenceCount(rendered, scoped); err != nil || references != 0 {
				t.Fatalf("reconciled requirements keep %d prior-layout references (%v): %s", references, err, rendered)
			}
			if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
				t.Fatalf("reconciled requirements do not verify: %v", err)
			}
		})
	}
}

// Isolation controls survive in the adopted preimage only on evidence that
// they predate DefenseClaw: the discarded record's trustworthy preimage of
// the same requirements file.
func TestWindowsCodexAdoptRequirementsKeepsIsolationControlsOnlyWithEvidence(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	scoped := testWindowsCodexScopedLayout()
	admin := []byte("allow_managed_hooks_only = true\nadministrator_key = \"preserve\"\n\n[features]\nhooks = true\n")
	stale, _, err := reconcileWindowsCodexRequirements(admin, scoped)
	if err != nil {
		t.Fatal(err)
	}
	keeps := func(preimage []byte) bool {
		cfg := mustParseWindowsCodexRequirements(t, preimage)
		features, _ := cfg["features"].(map[string]interface{})
		return cfg["allow_managed_hooks_only"] == true && features["hooks"] == true
	}

	trusted := testWindowsCodexDiscardedOwnership(t, scoped, admin)
	adoption, err := windowsCodexAdoptRequirements(stale, true, trusted, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !keeps(adoption.preimage) {
		t.Fatalf("administrator isolation controls dropped despite trusted evidence: %s", adoption.preimage)
	}

	for name, discarded := range map[string]*windowsCodexMachineOwnership{
		"hash mismatch": func() *windowsCodexMachineOwnership {
			record := testWindowsCodexDiscardedOwnership(t, scoped, admin)
			record.PreimageSHA256 = windowsCodexMachineHash([]byte("other"))
			return record
		}(),
		"other requirements file": func() *windowsCodexMachineOwnership {
			record := testWindowsCodexDiscardedOwnership(t, scoped, admin)
			record.RequirementsPath = `D:\Other\requirements.toml`
			return record
		}(),
		"no record": nil,
	} {
		t.Run(name, func(t *testing.T) {
			// Without a record only the current layout is recognizable.
			current := stale
			if discarded == nil {
				current, _, err = reconcileWindowsCodexRequirements(admin, opts)
				if err != nil {
					t.Fatal(err)
				}
			}
			adoption, err := windowsCodexAdoptRequirements(current, true, discarded, opts)
			if err != nil {
				t.Fatal(err)
			}
			cfg := mustParseWindowsCodexRequirements(t, adoption.preimage)
			if cfg["administrator_key"] != "preserve" || cfg["hooks"] != nil {
				t.Fatalf("adopted preimage %s", adoption.preimage)
			}
			if keeps(adoption.preimage) {
				t.Fatalf("isolation controls recorded as administrator settings without evidence: %s", adoption.preimage)
			}
		})
	}
}

// windowsCodexAdoptThenReconcile mirrors ReconcileWindowsCodexMachineRequirements
// with no ownership record: adopt, then reconcile the adopted base.
func windowsCodexAdoptThenReconcile(t *testing.T, current []byte, opts WindowsCodexMachineRequirementsOptions) (windowsCodexAdoption, []byte, error) {
	t.Helper()
	adoption, err := windowsCodexAdoptRequirements(current, true, nil, opts)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	rendered, _, err := reconcileWindowsCodexRequirements(adoption.base, opts)
	return adoption, rendered, err
}

// GAP-0015: with no ownership record, an administrator's own
// hooks.windows_managed_dir is refused, in strict and default trust modes,
// never overwritten. Only a directory the file itself proves DefenseClaw's
// (groups that run that directory's DefenseClaw hook launcher, left by a
// prior install whose record is gone) is reclaimed, and strict mode refuses
// even that.
func TestWindowsCodexReconcileForeignManagedDirNeedsDefenseClawEvidence(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = KnownHookContracts("codex")[0].ContractID
	administrator := []byte("[hooks]\nwindows_managed_dir = 'C:\\CorpHooks'\n\n[[hooks.PreToolUse]]\nmatcher = \"corp\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\CorpHooks\\audit.exe'\ntimeout = 5\n")
	scoped := testWindowsCodexScopedLayout()
	scoped.HookContractID = opts.HookContractID
	staleDefenseClaw, _, err := reconcileWindowsCodexRequirements([]byte("administrator_key = \"preserve\"\n"), scoped)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		current   []byte
		strict    string
		reclaimed bool
	}{
		{name: "administrator dir", current: administrator},
		{name: "administrator dir strict", current: administrator, strict: "1"},
		{name: "stale DefenseClaw dir", current: staleDefenseClaw, reclaimed: true},
		{name: "stale DefenseClaw dir strict", current: staleDefenseClaw, strict: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(managed.TrustStrictAncestorsEnv, tc.strict)
			adoption, rendered, err := windowsCodexAdoptThenReconcile(t, tc.current, opts)
			if !tc.reclaimed {
				if err == nil || !strings.Contains(err.Error(), "conflicts with protected managed directory") {
					t.Fatalf("foreign windows_managed_dir not refused (err=%v); rendered %d bytes", err, len(rendered))
				}
				if !bytes.Equal(adoption.preimage, tc.current) {
					t.Fatalf("refused adoption changed the preimage:\n%s", adoption.preimage)
				}
				return
			}
			if err != nil {
				t.Fatalf("stale DefenseClaw layout not reclaimed: %v", err)
			}
			if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
				t.Fatalf("reclaimed requirements do not verify: %v", err)
			}
			if references, err := windowsCodexOwnedPathReferenceCount(rendered, scoped); err != nil || references != 0 {
				t.Fatalf("reclaimed requirements keep %d stale references (%v)", references, err)
			}
			cfg := mustParseWindowsCodexRequirements(t, adoption.preimage)
			if !adoption.preimageExisted || cfg["administrator_key"] != "preserve" || cfg["hooks"] != nil {
				t.Fatalf("preimage keeps DefenseClaw content or lost the administrator's: %s", adoption.preimage)
			}
		})
	}
}

// GAP-0022: with no ownership record and no DefenseClaw hook in the file,
// an administrator's windows_managed_dir equal to DefenseClaw's ManagedDir
// is administrator content: the preimage is the file byte for byte, so an
// unchanged uninstall (exact postimage) restores exactly what was there.
func TestWindowsCodexAdoptRequirementsKeepsAdministratorManagedDir(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = KnownHookContracts("codex")[0].ContractID
	administrator := []byte("allow_managed_hooks_only = true\n\n[features]\nhooks = true\n\n[hooks]\nwindows_managed_dir = 'C:\\Program Files\\DefenseClaw\\bin'\n\n[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = 'C:\\Tools\\audit.exe'\ntimeout = 5\n")
	adoption, rendered, err := windowsCodexAdoptThenReconcile(t, administrator, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !adoption.preimageExisted || !bytes.Equal(adoption.preimage, administrator) {
		t.Fatalf("administrator file not kept byte for byte as the preimage:\n%s", adoption.preimage)
	}
	if !bytes.Equal(adoption.base, administrator) {
		t.Fatalf("adoption changed the live base:\n%s", adoption.base)
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
		t.Fatalf("reconciled requirements do not verify: %v", err)
	}
	// Once installed, the same administrator content next to DefenseClaw's
	// groups is still recognized: re-adoption (record lost again) yields the
	// same preimage, with the administrator's directory.
	readopted, err := windowsCodexAdoptRequirements(rendered, true, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := mustParseWindowsCodexRequirements(t, readopted.preimage)["hooks"].(map[string]interface{})
	if hooks["windows_managed_dir"] != opts.ManagedDir || hooks["PreToolUse"] == nil {
		t.Fatalf("re-adopted preimage lost administrator content: %s", readopted.preimage)
	}
}

// Ownership-absent adoption: a file DefenseClaw created is recorded as
// absent, so removal deletes it; a file with no DefenseClaw content is its
// own preimage.
func TestWindowsCodexAdoptRequirementsPreimageExistence(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = KnownHookContracts("codex")[0].ContractID
	created, _, err := reconcileWindowsCodexRequirements(nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	adoption, err := windowsCodexAdoptRequirements(created, true, nil, opts)
	if err != nil || adoption.preimageExisted || len(adoption.preimage) != 0 {
		t.Fatalf("created by DefenseClaw: %q, %t, %v", adoption.preimage, adoption.preimageExisted, err)
	}
	if !bytes.Equal(adoption.base, created) {
		t.Fatal("ownership-absent adoption changed the live base")
	}

	foreign := []byte("allow_managed_hooks_only = true\n\n[features]\nhooks = true\n")
	adoption, err = windowsCodexAdoptRequirements(foreign, true, nil, opts)
	if err != nil || !adoption.preimageExisted || !bytes.Equal(adoption.preimage, foreign) {
		t.Fatalf("no DefenseClaw content: %q, %t, %v", adoption.preimage, adoption.preimageExisted, err)
	}
	adoption, err = windowsCodexAdoptRequirements(nil, false, nil, opts)
	if err != nil || adoption.preimageExisted || len(adoption.preimage) != 0 {
		t.Fatalf("absent requirements: %q, %t, %v", adoption.preimage, adoption.preimageExisted, err)
	}
}
