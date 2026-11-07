// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0613: on a folder two connectors load, a skill denied by the second
// connector rule whose quarantine fails stays in the folder. The journal says
// so for the connector whose rule denied it as well as for the event owner,
// so neither is left without the install block.
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
	for _, connector := range []string{"amp", "codex"} {
		entry, err := store.GetActionForConnector("skill", "denied-skill", connector)
		if err != nil || entry == nil || entry.Actions.Install != "block" || !strings.HasPrefix(entry.Reason, "quarantine failed: ") {
			t.Errorf("%s journal = %+v (err %v), want install block with quarantine failed", connector, entry, err)
		}
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

func requireRuntimeHold(t *testing.T, w *InstallWatcher, held bool) {
	t.Helper()
	for _, connector := range []string{"amp", "codex"} {
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
	for _, connector := range []string{"amp", "codex"} {
		if entry, _ := w.store.GetActionForConnector("skill", "blocked-skill", connector); entry == nil || entry.Actions.Install != "block" ||
			!strings.HasPrefix(entry.Reason, "quarantine failed: ") || entry.SourcePath != evt.Path {
			t.Errorf("%s journal = %+v, want install block, quarantine failed reason and the source path", connector, entry)
		}
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
