// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-1458: a skill or plugin admitted with a MEDIUM warning stays in place
// and unchanged when the administrator then sets MEDIUM to an action that
// refuses (quarantine, block, a file-only quarantine or a runtime-only
// disable). The next rescan must decide its admission again and apply the
// refusal, not only scan it for drift. A loosened action refuses nothing,
// and a baseline recorded before 1.0.4 (no admission digest, as after an
// upgrade) runs no install admission.
func TestTightenedAdmissionRefusesAnUnchangedWarnedAsset(t *testing.T) {
	t.Setenv("PATH", "")
	warn := &config.AdmissionAction{Shorthand: config.AdmissionActionWarn}
	quarantine := &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	for _, kind := range []InstallType{InstallSkill, InstallPlugin} {
		for _, tc := range []struct {
			name   string
			medium *config.AdmissionAction
			legacy bool
			refuse bool
		}{
			{"quarantine", quarantine, false, true},
			{"block", &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}, false, true},
			{"file-only quarantine", &config.AdmissionAction{Triple: config.SeverityAction{
				Install: config.InstallNone, File: config.FileActionQuarantine, Runtime: config.RuntimeEnable,
			}}, false, true},
			{"runtime-only disable", &config.AdmissionAction{Triple: config.SeverityAction{
				Install: config.InstallNone, File: config.FileActionNone, Runtime: config.RuntimeDisable,
			}}, false, true},
			{"loosened to allow", &config.AdmissionAction{Shorthand: config.AdmissionActionAllow}, false, false},
			{"pre-1.0.4 baseline", quarantine, true, false},
		} {
			t.Run(string(kind)+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				cfg, store, logger, skillDir := setupTestEnv(t)
				cfg.Gateway.Watcher.Skill.TakeAction = true
				cfg.Gateway.Watcher.Plugin.TakeAction = true
				cfg.Watch.RescanContentGated = true
				layer := &cfg.Admission.Skill
				root := skillDir
				if kind == InstallPlugin {
					layer = &cfg.Admission.Plugin
					root = filepath.Join(cfg.DataDir, "plugins")
				}
				layer.Actions.Medium = warn
				dir := filepath.Join(root, "formatter")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("Format source with the configured formatter.\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				var w *InstallWatcher
				if kind == InstallSkill {
					w = New(cfg, []string{root}, nil, store, logger, nil, nil)
				} else {
					w = New(cfg, nil, []string{root}, store, logger, nil, nil)
				}
				w.scannerFactory = func(InstallEvent) scanner.Scanner {
					return &countingScanner{name: string(kind) + "-scanner", findings: []scanner.Finding{
						{ID: "f1", RuleID: "PERM-BROAD", Severity: scanner.SeverityMedium, Title: "broad permissions"},
					}}
				}
				evt := InstallEvent{Type: kind, Name: "formatter", Path: dir}
				res := w.runAdmission(ctx, evt)
				if res.Verdict != VerdictWarning {
					t.Fatalf("MEDIUM warn admission %+v, want warning", res)
				}
				snap, err := w.snapshotForEvent(evt)
				if err != nil {
					t.Fatal(err)
				}
				fp := w.scannerFingerprint(evt)
				if admissionDigest(fp) == "" {
					t.Fatalf("%s fingerprint %q carries no admission digest", kind, fp)
				}
				if tc.legacy {
					fp = strings.SplitN(fp, admissionDigestMark, 2)[0]
				}
				w.persistSnapshot(evt, snap, res.ScanID, fp)
				if !tc.legacy {
					if outcome := w.rescanTarget(ctx, evt, nil); outcome != rescanSkipped {
						t.Fatalf("unchanged admission rescan = %v, want skipped", outcome)
					}
				}

				layer.Actions.Medium = tc.medium
				if outcome := w.rescanTarget(ctx, evt, nil); outcome != rescanScanned {
					t.Fatalf("rescan after the admission change = %v, want scanned", outcome)
				}
				entry, err := store.GetActionForConnector(string(kind), evt.Name, w.journalScope(w.eventConnector(evt)))
				if err != nil {
					t.Fatal(err)
				}
				_, statErr := os.Stat(dir)
				refused := (entry != nil && !entry.Actions.IsEmpty()) || statErr != nil
				if refused != tc.refuse {
					t.Fatalf("refused=%v (journal %+v, stat %v), want %v", refused, entry, statErr, tc.refuse)
				}
			})
		}
	}
}

// The admission digest is apart from the scanner hash, survives the
// baseline marks the rescan appends, and is absent under Secure Client.
func TestAdmissionDigestInScannerFingerprint(t *testing.T) {
	if got := admissionDigest("abc" + admissionDigestMark + "0011" + unenforcedRejectionMark); got != "0011" {
		t.Fatalf("digest before a mark = %q", got)
	}
	if admissionDigest("abc"+interruptedAdmissionMark) != "" {
		t.Fatal("the interrupted-admission mark read as a digest")
	}
	if admissionPolicyChanged("abc", "abc"+admissionDigestMark+"01") {
		t.Fatal("a baseline without a digest (before 1.0.4) read as an admission change")
	}
	if !admissionPolicyChanged("abc"+admissionDigestMark+"01", "abc"+admissionDigestMark+"02") {
		t.Fatal("a changed digest did not read as an admission change")
	}
	cfg := &config.Config{}
	if admissionDigestSuffix(cfg, InstallMCP) == "" {
		t.Fatal("MCP fingerprint carries no admission digest")
	}
	cfg.Admission.MCP.Actions.Low = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	before := admissionDigestSuffix(&config.Config{}, InstallMCP)
	if admissionDigestSuffix(cfg, InstallMCP) == before {
		t.Fatal("a tightened MCP LOW kept the admission digest")
	}
}
