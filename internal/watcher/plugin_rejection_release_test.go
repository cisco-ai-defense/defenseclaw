// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-1911: a plugin the watcher rejected under an explicit admission
// high=block kept its auto-block (install block, runtime disable) after the
// administrator relaxed the setting and the user reinstalled it, although
// the new admission warned. A new admission that allows the plugin at the
// same path lifts only the watcher's own rejection; an operator block and a
// row for another path stay.
func TestRelaxedAdmissionReleasesTheWatchersOwnPluginRejection(t *testing.T) {
	judge := []scanner.Finding{{ID: "p1", RuleID: "LLM-OB-009-001", Severity: scanner.SeverityHigh, Title: "Supply chain risk"}}
	for _, tc := range []struct {
		name        string
		seed        func(t *testing.T, w *InstallWatcher, plugin string)
		wantCleared bool
	}{
		{name: "the watcher's own rejection", wantCleared: true},
		{name: "an operator block", seed: func(t *testing.T, w *InstallWatcher, plugin string) {
			if err := w.store.SetActionFieldForConnector("plugin", "r105fx", "claudecode", "install", "block", "manual block via CLI"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a rejection of another copy", seed: func(t *testing.T, w *InstallWatcher, plugin string) {
			_ = w.store.SetActionFieldForConnector("plugin", "r105fx", "claudecode", "install", "block", autoBlockReasonPrefix+"HIGH findings (scanner=plugin-scanner)")
			_ = w.store.SetSourcePathForConnector("plugin", "r105fx", "claudecode", filepath.Join(filepath.Dir(plugin), "other", "r105fx"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, skillDir := setupTestEnv(t)
			cfg.Gateway.Watcher.Plugin.TakeAction = true
			pluginDir := t.TempDir()
			plugin := filepath.Join(pluginDir, "r105fx")
			for rel, text := range map[string]string{
				".claude-plugin/plugin.json": `{"name":"r105fx","version":"1.0.0"}`,
				"skills/helper/SKILL.md":     "---\nname: helper\n---\nFormat notes.\n",
				"scripts/run.sh":             "#!/bin/sh\necho hi\n",
			} {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(plugin, rel)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(plugin, rel), []byte(text), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)
			w.scannerFactory = func(InstallEvent) scanner.Scanner {
				return &countingScanner{name: "plugin-scanner", findings: judge}
			}
			evt := InstallEvent{Type: InstallPlugin, Name: "r105fx", Path: plugin, Connector: "claudecode", Timestamp: time.Now()}
			if tc.seed == nil {
				cfg.Admission.Plugin.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}
				if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictRejected {
					t.Fatalf("explicit high=block: verdict %q (%s), want rejected", res.Verdict, res.Reason)
				}
				cfg.Admission.Plugin.Actions.High = nil
			} else {
				tc.seed(t, w, plugin)
			}
			before, err := store.GetActionForConnector("plugin", "r105fx", "claudecode")
			if err != nil || before == nil || before.Actions.Install != "block" {
				t.Fatalf("seeded row %+v (%v), want an install block", before, err)
			}
			if res := w.runAdmission(context.Background(), evt); res.Verdict != VerdictWarning {
				t.Fatalf("relaxed config: verdict %q (%s), want warning", res.Verdict, res.Reason)
			}
			after, err := store.GetActionForConnector("plugin", "r105fx", "claudecode")
			if err != nil {
				t.Fatal(err)
			}
			cleared := after == nil || after.Actions.IsEmpty()
			if cleared != tc.wantCleared {
				t.Fatalf("row after the warned admission %+v: cleared=%v, want %v", after, cleared, tc.wantCleared)
			}
		})
	}
}
