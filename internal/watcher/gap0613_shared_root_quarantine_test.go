// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0613: on a folder two connectors load, a skill denied by the second
// connector rule whose quarantine fails stays in the folder. The journal says
// so for the connector whose rule denied it. The root owner, whose rules allow
// the skill, is not held in the balanced tier: it runs the ordinary skill.
func TestGAP0613SharedRootDeniedSkillWhoseQuarantineFailsIsJournaledForTheDenyingConnector(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.AssetPolicy = config.DefaultAssetPolicy()
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "denied-skill", Connector: "codex"}}
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{skillDir: "amp"})
	w.SetRootConsumers([]RootConsumer{{"skill", skillDir, "amp"}, {"skill", skillDir, "codex"}})
	path := filepath.Join(skillDir, "denied-skill")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("---\nname: denied-skill\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.QuarantineDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.QuarantineDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.QuarantineDir, 0o700) })

	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "denied-skill", Path: path, Connector: "amp", Timestamp: time.Now()})
	if res.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %q, want blocked", res.Verdict)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected the skill to stay in place: %v", err)
	}
	entry, err := store.GetActionForConnector("skill", "denied-skill", "codex")
	if err != nil || entry == nil || entry.Actions.Install != "block" || !strings.HasPrefix(entry.Reason, "quarantine failed: ") {
		t.Errorf("codex journal = %+v (err %v), want install block with quarantine failed", entry, err)
	}
	if owner, err := store.GetActionForConnector("skill", "denied-skill", "amp"); err != nil || (owner != nil && (owner.Actions.Install != "" || owner.Actions.Runtime != "")) {
		t.Errorf("amp journal = %+v (err %v), want no hold for the owner whose rules allow the skill", owner, err)
	}
}

// sharedRootDefaultDenyWatcher is a folder amp owns and codex also loads,
// where codex alone denies every skill by default (no runtime_detection). With
// quarantineWorks false the quarantine store cannot be written, so a denied
// skill stays in place.
func sharedRootDefaultDenyWatcher(t *testing.T, quarantineWorks bool) (*InstallWatcher, *config.Config, InstallEvent) {
	t.Helper()
	cfg, store, logger, root := setupTestEnv(t)
	cfg.AssetPolicy = config.DefaultAssetPolicy()
	cfg.AssetPolicy.Enabled, cfg.AssetPolicy.Mode = true, config.AssetPolicyModeAction
	cfg.AssetPolicy.Connectors = map[string]config.PerConnectorAssetPolicy{
		"codex": {Skill: &config.PerConnectorAssetTypePolicy{Default: "deny"}},
	}
	if !quarantineWorks {
		cfg.QuarantineDir = filepath.Join(cfg.DataDir, "quarantine-is-file")
		if err := os.WriteFile(cfg.QuarantineDir, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	skill := filepath.Join(root, "blocked-skill")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: blocked-skill\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "amp"})
	w.SetRootConsumers([]RootConsumer{{"skill", root, "amp"}, {"skill", root, "codex"}})
	return w, cfg, InstallEvent{Type: InstallSkill, Name: "blocked-skill", Path: skill, Connector: "amp", Timestamp: time.Now()}
}

// requireRuntimeHold checks the runtime hold of the denying connector (codex)
// and that the root owner (amp), whose rules allow the skill, is never held.
func requireRuntimeHold(t *testing.T, w *InstallWatcher, held bool) {
	t.Helper()
	requireRuntimeHoldFor(t, w, held, "codex")
	requireRuntimeHoldFor(t, w, false, "amp")
}

func requireRuntimeHoldFor(t *testing.T, w *InstallWatcher, held bool, connectors ...string) {
	t.Helper()
	for _, connector := range connectors {
		disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", "blocked-skill", connector)
		if err != nil || disabled != held {
			entry, _ := w.store.GetActionForConnector("skill", "blocked-skill", connector)
			t.Errorf("%s runtime disabled = %v (err %v), want %v; journal %+v", connector, disabled, err, held, entry)
		}
	}
}

// reloadAfterScan swaps the admission policy for denying once the scan has
// run, as a config reload during the scan would.
func reloadAfterScan(w *InstallWatcher, allowing, denying *config.Config) {
	var reloaded atomic.Bool
	w.admissionPolicySource = func() AdmissionPolicySnapshot {
		if reloaded.Load() {
			return AdmissionPolicySnapshot{Config: denying}
		}
		return AdmissionPolicySnapshot{Config: allowing}
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &reloadingScanner{countingScanner: countingScanner{name: "skill-scanner"}, onScan: func() { reloaded.Store(true) }}
	}
}

// GAP-0613 review 9: a skill the second consumer denies by default stays in
// the folder when its quarantine fails; the hook checks the runtime disable
// without runtime_detection, so the journal carries it for the denying
// consumer and the owner, not just the install block.
func TestGAP0613SharedRootDefaultDenyWhoseQuarantineFailsIsDisabledAtRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	w, _, evt := sharedRootDefaultDenyWatcher(t, false)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	if _, err := os.Lstat(evt.Path); err != nil {
		t.Fatalf("expected the skill to stay in place: %v", err)
	}
	requireRuntimeHold(t, w, true)
	if entry, _ := w.store.GetActionForConnector("skill", "blocked-skill", "codex"); entry == nil || entry.Actions.Install != "block" ||
		!strings.HasPrefix(entry.Reason, "quarantine failed: ") || entry.SourcePath != evt.Path {
		t.Errorf("codex journal = %+v, want install block, quarantine failed reason and the source path", entry)
	}
}

// The same denial caught after the scan (a reload switched the default deny
// on while the skill was scanned) holds the skill at runtime too.
func TestGAP0613SharedRootPostScanDefaultDenyWhoseQuarantineFailsIsDisabledAtRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	allowing := *cfg
	allowing.AssetPolicy = config.DefaultAssetPolicy()
	allowing.AssetPolicy.Enabled, allowing.AssetPolicy.Mode = true, config.AssetPolicyModeAction
	reloadAfterScan(w, &allowing, cfg)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	requireRuntimeHold(t, w, true)
}

// A denial by the owner itself after the scan is journaled and held too; the
// owner case was skipped.
func TestGAP0613OwnerPostScanDenyWhoseQuarantineFailsIsDisabledAtRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	w.SetRootConsumers(nil)
	denying := *cfg
	denying.AssetPolicy.Connectors = map[string]config.PerConnectorAssetPolicy{
		"amp": {Skill: &config.PerConnectorAssetTypePolicy{Default: "deny"}},
	}
	allowing := *cfg
	allowing.AssetPolicy = config.DefaultAssetPolicy()
	allowing.AssetPolicy.Enabled, allowing.AssetPolicy.Mode = true, config.AssetPolicyModeAction
	reloadAfterScan(w, &allowing, &denying)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	if disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", "blocked-skill", "amp"); err != nil || !disabled {
		t.Errorf("amp runtime disabled = %v (err %v), want true", disabled, err)
	}
}

// Benign twin: when the quarantine works the skill is gone, so no runtime
// disable is left behind to outlive a later policy change.
func TestGAP0613SharedRootDefaultDenyThatQuarantinesLeavesNoRuntimeDisable(t *testing.T) {
	w, _, evt := sharedRootDefaultDenyWatcher(t, true)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	if _, err := os.Lstat(evt.Path); !os.IsNotExist(err) {
		t.Fatalf("expected the skill to be quarantined, lstat err = %v", err)
	}
	requireRuntimeHold(t, w, false)
}

func requireJournalClear(t *testing.T, w *InstallWatcher) {
	t.Helper()
	for _, connector := range []string{"amp", "codex"} {
		entry, err := w.store.GetActionForConnector("skill", "blocked-skill", connector)
		if err != nil || (entry != nil && (entry.Actions.Install != "" || entry.Actions.Runtime != "")) {
			t.Errorf("%s journal = %+v (err %v), want no install block and no runtime disable", connector, entry, err)
		}
	}
}

// GAP-0613 review 10: the runtime hold a denial left on the denying consumer
// is lifted along with the owner row when the denial goes, whatever lifts it:
// a global allow rule, an allow rule scoped to the denying connector, or a
// default that no longer denies. The rescan notices it without a new copy.
func TestGAP0613SharedRootPolicyHoldIsLiftedForEveryConnectorWhenTheDenialGoes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	for _, tc := range []struct {
		name  string
		relax func(cfg *config.Config)
	}{
		{"global allow rule", func(cfg *config.Config) {
			cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "blocked-skill"}}
		}},
		{"allow rule scoped to the denying connector", func(cfg *config.Config) {
			cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "blocked-skill", Connector: "codex"}}
		}},
		{"default no longer denies", func(cfg *config.Config) {
			cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
			if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
				t.Fatalf("admission = %+v, want blocked", res)
			}
			requireRuntimeHold(t, w, true)
			if w.policyHoldReleases(evt) {
				t.Fatal("the rescan would lift a hold while the default deny stands")
			}
			tc.relax(cfg)
			if !w.policyHoldReleases(evt) {
				t.Fatal("the rescan does not notice that no rule denies the held skill")
			}
			w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
			if res := w.runAdmission(context.Background(), evt); res.Verdict == VerdictBlocked {
				t.Fatalf("admission = %+v, want the skill admitted", res)
			}
			requireRuntimeHold(t, w, false)
			requireJournalClear(t, w)
			if w.policyHoldReleases(evt) {
				t.Error("the rescan still sees a hold after it was lifted")
			}
		})
	}
}

// A denied copy that an operator restored stays in its folder while the
// owner install block stands. The connector whose default deny applies still
// gets the runtime disable, which the hook enforces without
// runtime_detection; before, no row was written for it and the copy stayed
// callable.
func TestGAP0613SharedRootDeniedRestoredCopyIsDisabledAtRuntimeForTheDenyingConnector(t *testing.T) {
	w, _, evt := sharedRootDefaultDenyWatcher(t, true)
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "install", "block", "blocked by an earlier scan"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", evt.Path); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	if _, err := os.Lstat(evt.Path); err != nil {
		t.Fatalf("the restored copy must stay in place: %v", err)
	}
	requireRuntimeHold(t, w, true)
	entry, _ := w.store.GetActionForConnector("skill", evt.Name, "codex")
	if entry == nil || entry.Actions.Install != "block" || entry.SourcePath != evt.Path || len(heldFieldsOf(entry.Reason)) == 0 {
		t.Errorf("codex journal = %+v, want install block, runtime disable and the source path", entry)
	}
	// The hold does not make the next admission quarantine the restored copy.
	if !w.preserveRestoredBlockedAsset(evt) {
		t.Error("the restored copy lost its restore exception")
	}
}

// Benign twin: a block no asset policy denial wrote (a failed scan-verdict
// quarantine) is not lifted merely because the policy does not deny the
// skill.
func TestGAP0613ScanVerdictBlockIsNotAPolicyHold(t *testing.T) {
	w, _, evt := sharedRootDefaultDenyWatcher(t, true)
	w.SetRootConsumers(nil)
	w.journalFailedQuarantine(evt, "skill", os.ErrPermission)
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", evt.Path); err != nil {
		t.Fatal(err)
	}
	if scopes := w.policyHeldScopes(evt); len(scopes) != 0 {
		t.Errorf("policy holds = %v, want none for a scan-verdict block", scopes)
	}
	if w.policyHoldReleases(evt) {
		t.Error("the rescan would lift a block that no policy denial wrote")
	}
}

// holdScanner runs onScan, which sees the journal while the scan is on.
type holdScanner struct {
	countingScanner
	onScan func(ctx context.Context) error
}

func (s *holdScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	if err := s.onScan(ctx); err != nil {
		return nil, err
	}
	return s.countingScanner.Scan(ctx, target)
}

func relaxCodexDefault(cfg *config.Config) {
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"}}
}

func codexDisabled(t *testing.T, w *InstallWatcher) bool {
	t.Helper()
	disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", "blocked-skill", "codex")
	if err != nil {
		t.Fatal(err)
	}
	return disabled
}

// GAP-0613 review 11: the hold on a skill that stayed in its folder is lifted
// when admission reaches a verdict that lets it run, not before the scan: the
// skill stays disabled while the replacement scan runs, and a scan that finds
// a critical issue or is cut off keeps the hold.
func TestGAP0613PolicyHoldStaysUntilTheReplacementScanAllows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	critical := []scanner.Finding{{ID: "f1", RuleID: "SKILL-001", Severity: scanner.SeverityCritical, Title: "critical finding"}}
	for _, tc := range []struct {
		name     string
		findings []scanner.Finding
		cancel   bool
		wantHeld bool
	}{
		{"clean scan lifts it", nil, false, false},
		{"critical finding keeps it", critical, false, true},
		{"interrupted scan keeps it", nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
			if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
				t.Fatalf("admission = %+v, want blocked", res)
			}
			relaxCodexDefault(cfg)
			var heldDuringScan bool
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w.scannerFactory = func(InstallEvent) scanner.Scanner {
				return &holdScanner{
					countingScanner: countingScanner{name: "skill-scanner", findings: tc.findings},
					onScan: func(ctx context.Context) error {
						heldDuringScan = codexDisabled(t, w)
						if tc.cancel {
							cancel()
							return ctx.Err()
						}
						return nil
					},
				}
			}
			w.runAdmission(ctx, evt)
			if !heldDuringScan {
				t.Error("the hold was lifted before the replacement scan ran")
			}
			if got := codexDisabled(t, w); got != tc.wantHeld {
				t.Errorf("codex runtime disabled after admission = %v, want %v", got, tc.wantHeld)
			}
		})
	}
}

// GAP-0613 review 11: OpenClaw's install journal is the global row, which
// every connector's runtime check falls back to. When OpenClaw is the
// connector whose rule denies the skill, its runtime disable is on its own
// row: an unrelated connector's skill of the same name stays usable, the root
// owner whose rules allow it included. The
// install block keeps its legacy global row, and the hold lifts from both.
func TestGAP0613OpenClawPolicyHoldDoesNotDisableAnotherConnectorsSkill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	cfg.AssetPolicy.Connectors = map[string]config.PerConnectorAssetPolicy{
		"openclaw": {Skill: &config.PerConnectorAssetTypePolicy{Default: "deny"}},
	}
	w.SetRootConsumers([]RootConsumer{{"skill", filepath.Dir(evt.Path), "amp"}, {"skill", filepath.Dir(evt.Path), "openclaw"}})
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	pe := enforce.NewPolicyEngine(w.store)
	for connector, want := range map[string]bool{"amp": false, "openclaw": true, "hermes": false, "": false} {
		if got, err := pe.IsDisabledForConnector("skill", "blocked-skill", connector); err != nil || got != want {
			t.Errorf("%q runtime disabled = %v (err %v), want %v", connector, got, err, want)
		}
	}
	if global, _ := w.store.GetActionForConnector("skill", "blocked-skill", ""); global == nil || global.Actions.Install != "block" || global.Actions.Runtime != "" {
		t.Errorf("global journal = %+v, want the legacy install block only", global)
	}
	cfg.AssetPolicy.Connectors["openclaw"] = config.PerConnectorAssetPolicy{Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"}}
	if !w.policyHoldReleases(evt) {
		t.Fatal("the rescan does not notice the lifted denial")
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	w.runAdmission(context.Background(), evt)
	for _, scope := range []string{"", "amp", "openclaw"} {
		if entry, _ := w.store.GetActionForConnector("skill", "blocked-skill", scope); entry != nil && (entry.Actions.Install != "" || entry.Actions.Runtime != "") {
			t.Errorf("%q journal = %+v after the release, want no hold", scope, entry)
		}
	}
}

// GAP-0613 review 11: a runtime disable on a row for another reason (an
// operator's) is not part of the policy hold. Lifting the hold clears what the
// hold set and leaves that disable, with its reason.
func TestGAP0613PolicyReleaseKeepsAnEarlierRuntimeBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the quarantine store is made unwritable with a file")
	}
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	if err := w.store.SetActionFieldForConnector("skill", "blocked-skill", "amp", "runtime", "disable", "disabled by the operator"); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("admission = %+v, want blocked", res)
	}
	requireRuntimeHoldFor(t, w, true, "codex")
	relaxCodexDefault(cfg)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	w.runAdmission(context.Background(), evt)
	if codexDisabled(t, w) {
		t.Error("codex is still disabled after the hold was lifted")
	}
	entry, _ := w.store.GetActionForConnector("skill", "blocked-skill", "amp")
	if entry == nil || entry.Actions.Runtime != "disable" || entry.Actions.Install != "" || entry.Reason != "disabled by the operator" {
		t.Errorf("amp journal = %+v, want the operator's runtime disable and its reason, no install block", entry)
	}
}

// A valid earlier runtime=enable row is a usable skill, not a protective
// disable. A later enforced default deny must replace it while the denied
// copy remains in its folder after quarantine fails.
func TestGAP0613PolicyDenyOverridesEarlierRuntimeEnable(t *testing.T) {
	w, _, evt := sharedRootDefaultDenyWatcher(t, false)
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "codex", "runtime", "enable", "operator previously enabled"); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("denial verdict = %+v, want blocked", res)
	}
	if _, err := os.Lstat(evt.Path); err != nil {
		t.Fatalf("denied copy should remain after failed quarantine: %v", err)
	}
	disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", evt.Name, "codex")
	if err != nil || !disabled {
		entry, _ := w.store.GetActionForConnector("skill", evt.Name, "codex")
		t.Errorf("codex protected skill is callable: disabled=%v err=%v row=%+v", disabled, err, entry)
	}
}

// An independent install block must not be claimed by a later policy hold.
// Relaxing that policy after a clean scan does not remove an earlier manual
// install block which no policy change authorized the watcher to lift.
func TestGAP0613PolicyReleaseKeepsEarlierInstallBlock(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "install", "block", "operator blocked this skill"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", evt.Path); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("denial verdict = %+v, want blocked", res)
	}
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{
		Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"},
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	res := w.runAdmission(context.Background(), evt)
	if res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected || res.Verdict == VerdictScanError {
		t.Fatalf("replacement scan = %+v, want allowed or clean", res)
	}
	entry, err := w.store.GetActionForConnector("skill", evt.Name, "amp")
	if err != nil || entry == nil || entry.Actions.Install != "block" || entry.Reason != "operator blocked this skill" {
		t.Errorf("prior install block erased by policy release: row=%+v err=%v", entry, err)
	}
}

// Control: ordinary clean admission does not erase an operator install block.
func TestGAP0613ManualInstallBlockSurvivesCleanRescanWithoutPolicyHold(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{
		Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"},
	}
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "install", "block", "operator blocked this skill"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", evt.Path); err != nil {
		t.Fatal(err)
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	res := w.runAdmission(context.Background(), evt)
	if res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected || res.Verdict == VerdictScanError {
		t.Fatalf("clean scan = %+v", res)
	}
	entry, err := w.store.GetActionForConnector("skill", evt.Name, "amp")
	if err != nil || entry == nil || entry.Actions.Install != "block" || entry.Reason != "operator blocked this skill" {
		t.Errorf("control: operator install block not retained: row=%+v err=%v", entry, err)
	}
}

// The same runtime-enable hole applies when the owner itself has the deny.
func TestGAP0613OwnerDenyOverridesEarlierRuntimeEnable(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	cfg.AssetPolicy.Connectors = map[string]config.PerConnectorAssetPolicy{
		"amp": {Skill: &config.PerConnectorAssetTypePolicy{Default: "deny"}},
	}
	w.SetRootConsumers(nil)
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "runtime", "enable", "operator previously enabled"); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("denial verdict = %+v, want blocked", res)
	}
	if _, err := os.Lstat(evt.Path); err != nil {
		t.Fatalf("denied copy should remain after failed quarantine: %v", err)
	}
	disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", evt.Name, "amp")
	if err != nil || !disabled {
		entry, _ := w.store.GetActionForConnector("skill", evt.Name, "amp")
		t.Errorf("owner's protected skill is callable: disabled=%v err=%v row=%+v", disabled, err, entry)
	}
}

// The committed scan-verdict control covers a block with no policy hold.
// Exercise the adjacent lifecycle: a later policy denial must not take
// ownership of that existing install block and erase it when policy relaxes.
func TestGAP0613PolicyReleaseKeepsEarlierScanVerdictInstallBlock(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	w.journalFailedQuarantine(evt, "skill", os.ErrPermission)
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", evt.Path); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("policy denial = %+v, want blocked", res)
	}
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{
		Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"},
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	res := w.runAdmission(context.Background(), evt)
	if res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected || res.Verdict == VerdictScanError {
		t.Fatalf("replacement scan = %+v, want allowed or clean", res)
	}
	entry, err := w.store.GetActionForConnector("skill", evt.Name, "amp")
	if err != nil || entry == nil || entry.Actions.Install != "block" || !strings.HasPrefix(entry.Reason, quarantineFailedReason) {
		t.Errorf("earlier scan-verdict install block erased by policy release: row=%+v err=%v", entry, err)
	}
}

// A policy hold for source B must not rebind an independent runtime block
// pinned to source A. Otherwise a later allow for B can erase A's block.
func TestGAP0613PolicyHoldKeepsEarlierRuntimeBlockSourcePath(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	priorPath := filepath.Join(filepath.Dir(evt.Path), "earlier-location", evt.Name)
	if err := os.MkdirAll(priorPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(priorPath, "SKILL.md"), []byte("---\nname: blocked-skill\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "runtime", "disable", "operator blocked earlier location"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", priorPath); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("policy denial = %+v, want blocked", res)
	}
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{
		Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"},
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	if res := w.runAdmission(context.Background(), evt); res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected || res.Verdict == VerdictScanError {
		t.Fatalf("replacement scan = %+v, want allowed or clean", res)
	}
	entry, err := w.store.GetActionForConnector("skill", evt.Name, "amp")
	if err != nil || entry == nil || entry.Actions.Runtime != "disable" || entry.SourcePath != priorPath {
		t.Errorf("earlier block lost its source path: row=%+v err=%v, want %q", entry, err, priorPath)
	}
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: evt.Name, SourcePathContains: []string{evt.Path}}}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictAllowed {
		t.Fatalf("source-B allow rule = %+v, want allowed", res)
	}
	disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", evt.Name, "amp")
	if err != nil || !disabled {
		t.Errorf("source-B allow erased source-A runtime block: disabled=%v err=%v", disabled, err)
	}
}

// Control: without the intervening policy hold, B's pinned allow leaves A's
// runtime disable in place because the journal source path is still A.
func TestGAP0613SourcePinnedAllowKeepsDifferentRuntimeBlockControl(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	priorPath := filepath.Join(filepath.Dir(evt.Path), "earlier-location", evt.Name)
	if err := os.MkdirAll(priorPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{
		Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"},
	}
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: evt.Name, SourcePathContains: []string{evt.Path}}}
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "runtime", "disable", "operator blocked earlier location"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", priorPath); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictAllowed {
		t.Fatalf("source-B allow rule = %+v, want allowed", res)
	}
	disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", evt.Name, "amp")
	if err != nil || !disabled {
		t.Errorf("control: source-B allow erased source-A runtime block: disabled=%v err=%v", disabled, err)
	}
}

// Benign twin: the hold that replaced an earlier runtime enable is lifted when
// the denial goes, so relaxing the policy leaves the skill callable.
func TestGAP0613PolicyHoldOverEarlierRuntimeEnableLiftsWithTheDenial(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "codex", "runtime", "enable", "operator previously enabled"); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("denial verdict = %+v, want blocked", res)
	}
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{
		Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"},
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	if res := w.runAdmission(context.Background(), evt); res.Verdict == VerdictBlocked || res.Verdict == VerdictRejected || res.Verdict == VerdictScanError {
		t.Fatalf("replacement scan = %+v, want allowed or clean", res)
	}
	disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", evt.Name, "codex")
	if err != nil || disabled {
		entry, _ := w.store.GetActionForConnector("skill", evt.Name, "codex")
		t.Errorf("skill stays blocked after the denial went: disabled=%v err=%v row=%+v", disabled, err, entry)
	}
}

func heldFieldsOf(reason string) []string {
	fields, _ := parsePolicyHold(reason)
	return fields
}

// writeSkillCopy puts a second copy of the skill at path.
func writeSkillCopy(t *testing.T, path, name string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func notDenied(v Verdict) bool {
	return v != VerdictBlocked && v != VerdictRejected && v != VerdictScanError
}

// An operator's install block is pinned to copy A. A policy denial of copy B
// whose quarantine fails adds a runtime hold for B only; when B is admitted
// clean the hold goes with it, and A's block stays.
func TestGAP0613PinnedInstallBlockDoesNotStrandRuntimeHoldOnOtherCopy(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	priorPath := filepath.Join(filepath.Dir(evt.Path), "earlier-location", evt.Name)
	writeSkillCopy(t, priorPath, evt.Name)
	if err := w.store.SetActionFieldForConnector("skill", evt.Name, "amp", "install", "block", "operator blocked source A"); err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetSourcePathForConnector("skill", evt.Name, "amp", priorPath); err != nil {
		t.Fatal(err)
	}
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("source B denial = %+v, want blocked", res)
	}
	cfg.AssetPolicy.Connectors["codex"] = config.PerConnectorAssetPolicy{Skill: &config.PerConnectorAssetTypePolicy{Default: "allow"}}
	if !w.policyHoldReleases(evt) {
		t.Error("the rescan does not notice source B's releasable hold")
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	if res := w.runAdmission(context.Background(), evt); !notDenied(res.Verdict) {
		t.Fatalf("source B replacement scan = %+v, want clean or allowed", res)
	}
	pe := enforce.NewPolicyEngine(w.store)
	for _, connector := range []string{"amp", "codex"} {
		if disabled, err := pe.IsDisabledForConnector("skill", evt.Name, connector); err != nil || disabled {
			amp, _ := w.store.GetActionForConnector("skill", evt.Name, "amp")
			t.Errorf("clean source B still runtime blocked for %s: disabled=%v err=%v amp=%+v", connector, disabled, err, amp)
		}
	}
	amp, err := w.store.GetActionForConnector("skill", evt.Name, "amp")
	if err != nil || amp == nil || amp.Actions.Install != "block" || amp.SourcePath != priorPath || amp.Reason != "operator blocked source A" {
		t.Errorf("source A's independent install block changed: amp=%+v err=%v", amp, err)
	}
}

// Two copies of one name are denied by the same default rule and both stay in
// place. An allow rule scoped to the second copy admits it and leaves the
// first one held, since the first is still denied.
func TestGAP0613AllowForSecondDeniedCopyKeepsTheFirstCopyHeld(t *testing.T) {
	w, cfg, first := sharedRootDefaultDenyWatcher(t, false)
	firstRoot := filepath.Dir(first.Path)
	secondRoot := filepath.Join(filepath.Dir(firstRoot), "second-skill-root")
	second := first
	second.Path = filepath.Join(secondRoot, first.Name)
	writeSkillCopy(t, second.Path, first.Name)
	w.skillDirs = append(w.skillDirs, secondRoot)
	w.SetRootConnectors(map[string]string{firstRoot: "amp", secondRoot: "amp"})
	w.SetRootConsumers([]RootConsumer{
		{"skill", firstRoot, "amp"}, {"skill", firstRoot, "codex"},
		{"skill", secondRoot, "amp"}, {"skill", secondRoot, "codex"},
	})
	pe := enforce.NewPolicyEngine(w.store)
	for _, evt := range []InstallEvent{first, second} {
		if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
			t.Fatalf("policy denial of %s = %+v, want blocked", evt.Path, res)
		}
	}
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: second.Name, Connector: "codex", SourcePathContains: []string{second.Path}}}
	if !w.policyDenies(first) || w.policyDenies(second) {
		t.Fatalf("source-scoped allow: first denied=%v second denied=%v, want true and false", w.policyDenies(first), w.policyDenies(second))
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	if res := w.runAdmission(context.Background(), second); !notDenied(res.Verdict) {
		t.Fatalf("second copy source allow = %+v, want admitted", res)
	}
	if disabled, err := pe.IsDisabledForConnector("skill", first.Name, "codex"); err != nil || !disabled {
		amp, _ := w.store.GetActionForConnector("skill", first.Name, "amp")
		codex, _ := w.store.GetActionForConnector("skill", first.Name, "codex")
		t.Errorf("first copy callable while its default deny stands: disabled=%v err=%v amp=%+v codex=%+v", disabled, err, amp, codex)
	}
	// Benign twin: once the rule that denies the first copy goes too, the
	// rescan of the first copy lifts the hold.
	relaxCodexDefault(cfg)
	if !w.policyHoldReleases(first) {
		t.Error("the rescan does not notice the first copy's releasable hold")
	}
	if res := w.runAdmission(context.Background(), first); !notDenied(res.Verdict) {
		t.Fatalf("first copy replacement scan = %+v, want clean or allowed", res)
	}
	requireRuntimeHold(t, w, false)
	requireJournalClear(t, w)
}

// denyAmpSkillsByDefault makes the root owner deny every skill as codex does.
func denyAmpSkillsByDefault(cfg *config.Config) {
	cfg.AssetPolicy.Connectors["amp"] = config.PerConnectorAssetPolicy{Skill: &config.PerConnectorAssetTypePolicy{Default: "deny"}}
}

// A copy that stays in the folder after a failed quarantine is loadable by
// every connector that loads the root. When two of them deny it, each one
// holds it, not only the owner and the first denier.
func TestGAP0613EveryDenyingConnectorHoldsACopyWhoseQuarantineFails(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	denyAmpSkillsByDefault(cfg)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %+v, want blocked", res)
	}
	requireRuntimeHoldFor(t, w, true, "amp", "codex")
	for _, connector := range []string{"amp", "codex"} {
		if entry, err := w.store.GetActionForConnector("skill", evt.Name, connector); err != nil || entry == nil || entry.Actions.Install != "block" {
			t.Errorf("%s journal = %+v (err %v), want the install block", connector, entry, err)
		}
	}
	// Both denials go: the hold is lifted from both rows.
	relaxCodexDefault(cfg)
	cfg.AssetPolicy.Connectors["amp"] = cfg.AssetPolicy.Connectors["codex"]
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	if !w.policyHoldReleases(evt) {
		t.Error("the rescan does not notice the releasable hold")
	}
	if res := w.runAdmission(context.Background(), evt); !notDenied(res.Verdict) {
		t.Fatalf("replacement scan = %+v, want clean or allowed", res)
	}
	requireRuntimeHold(t, w, false)
	requireJournalClear(t, w)
}

// Benign twins: a connector whose rules allow the copy is not held because
// another connector denies it, and a denial whose quarantine works leaves no
// hold on any row.
func TestGAP0613ConnectorThatAllowsTheCopyIsNotHeldByAnotherConnectorsDenial(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, false)
	relaxCodexDefault(cfg)
	denyAmpSkillsByDefault(cfg)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %+v, want blocked", res)
	}
	if disabled, err := enforce.NewPolicyEngine(w.store).IsDisabledForConnector("skill", evt.Name, "amp"); err != nil || !disabled {
		t.Errorf("amp runtime disabled = %v (err %v), want true", disabled, err)
	}
	if codexDisabled(t, w) {
		entry, _ := w.store.GetActionForConnector("skill", evt.Name, "codex")
		t.Errorf("codex allows the copy but is held: %+v", entry)
	}
}

func TestGAP0613EveryDenyingConnectorLeavesNoHoldWhenTheQuarantineWorks(t *testing.T) {
	w, cfg, evt := sharedRootDefaultDenyWatcher(t, true)
	denyAmpSkillsByDefault(cfg)
	if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %+v, want blocked", res)
	}
	requireRuntimeHold(t, w, false)
}

// The hold tag is read by the gateway, which cannot see the watcher
// constants; its test builds a reason in this shape.
func TestGAP0613PolicyHoldTagShape(t *testing.T) {
	if got, want := policyDenialMark([]string{"install", "runtime"}, []string{"YQ", "Yg"}), " [asset policy: install,runtime copies=YQ,Yg]"; got != want {
		t.Errorf("policyDenialMark = %q, want %q", got, want)
	}
}

// A hold covers the copies it was written for. Another copy of the name that
// an allow rule admitted is outside it; the held copy, a path below it, a
// link to it and any path that cannot be placed are not.
func TestGAP0613PolicyHoldCoversOnlyTheHeldCopies(t *testing.T) {
	w, cfg, first := sharedRootDefaultDenyWatcher(t, false)
	firstRoot := filepath.Dir(first.Path)
	secondRoot := filepath.Join(filepath.Dir(firstRoot), "second-skill-root")
	second := first
	second.Path = filepath.Join(secondRoot, first.Name)
	writeSkillCopy(t, second.Path, first.Name)
	w.skillDirs = append(w.skillDirs, secondRoot)
	w.SetRootConnectors(map[string]string{firstRoot: "amp", secondRoot: "amp"})
	w.SetRootConsumers([]RootConsumer{
		{"skill", firstRoot, "amp"}, {"skill", firstRoot, "codex"},
		{"skill", secondRoot, "amp"}, {"skill", secondRoot, "codex"},
	})
	for _, evt := range []InstallEvent{first, second} {
		if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictBlocked {
			t.Fatalf("policy denial of %s = %+v, want blocked", evt.Path, res)
		}
	}
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: second.Name, Connector: "codex", SourcePathContains: []string{second.Path}}}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "skill-scanner"} }
	if res := w.runAdmission(context.Background(), second); !notDenied(res.Verdict) {
		t.Fatalf("second copy source allow = %+v, want admitted", res)
	}
	entry, err := w.store.GetActionForConnector("skill", first.Name, "codex")
	if err != nil || entry == nil || entry.Actions.Runtime != "disable" {
		t.Fatalf("codex row = %+v (err %v), want the first copy runtime hold", entry, err)
	}
	check := func(label string, want bool, paths ...string) {
		t.Helper()
		if got := slices.Contains(PolicyHoldIgnoredFields(entry, paths).Ignored, "runtime"); got != want {
			t.Errorf("%s: hold ignored = %v, want %v", label, got, want)
		}
	}
	check("admitted second copy", true, second.Path)
	check("file in the admitted second copy", true, filepath.Join(second.Path, "SKILL.md"))
	check("held first copy", false, first.Path)
	check("file in the held first copy", false, filepath.Join(first.Path, "SKILL.md"))
	check("both copies named", false, second.Path, first.Path)
	check("no path", false)
	check("empty path", false, "")
	check("relative path", false, filepath.Join("skills", first.Name))
	check("parent element", false, second.Path+string(filepath.Separator)+".."+string(filepath.Separator)+first.Name)
	if runtime.GOOS != "windows" {
		link := filepath.Join(secondRoot, "alias-of-first")
		if err := os.Symlink(first.Path, link); err != nil {
			t.Fatal(err)
		}
		check("link to the held first copy", false, filepath.Join(link, "SKILL.md"))
	}
	if len(PolicyHoldIgnoredFields(&audit.ActionEntry{Reason: "operator disabled"}, []string{second.Path}).Ignored) != 0 {
		t.Error("a row with no hold ignored a path")
	}
}
