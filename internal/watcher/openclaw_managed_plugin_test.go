// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestR108G501OpenClawManagedLinkOneDecision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a link without elevated privileges")
	}
	for _, blocked := range []bool{false, true} {
		name := "published"
		if blocked {
			name = "changed"
		}
		t.Run(name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Gateway.Watcher.Plugin.TakeAction = true
			cfg.Watch.RescanEnabled = true
			cfg.Watch.RescanContentGated = true
			home := t.TempDir()
			extensions := filepath.Join(home, ".openclaw", "extensions")
			packageRoot := filepath.Join(home, ".openclaw", "npm", "projects", "provider", "node_modules", "@openclaw", "amazon-bedrock-provider")
			for _, path := range []string{extensions, packageRoot} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(packageRoot, "package.json"), []byte(`{"name":"@openclaw/amazon-bedrock-provider","version":"2026.10.9"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(extensions, "amazon-bedrock")
			if err := os.Symlink(packageRoot, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			w := New(cfg, nil, []string{extensions}, store, logger, nil, nil)
			w.SetRootConnectors(map[string]string{extensions: "openclaw"})
			w.SetAssetOwners([]AssetOwner{{Home: home}})
			scan := &countingScanner{name: "plugin-scanner"}
			if blocked {
				scan.findings = []scanner.Finding{{ID: "f1", RuleID: "SRC-EXEC", Severity: scanner.SeverityHigh, Title: "Calls exec()"}}
			}
			w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
			evt := InstallEvent{Type: InstallPlugin, Name: "amazon-bedrock", Path: link, Connector: "openclaw", Timestamp: time.Now()}
			snap := w.admissionSnapshot(evt)
			if snap == nil {
				t.Fatal("managed package did not produce an admission snapshot")
			}
			res := w.runAdmission(context.Background(), evt)
			if scan.calls != 1 || res.ScanID == "" {
				t.Fatalf("scans=%d scan_id=%q verdict=%s", scan.calls, res.ScanID, res.Verdict)
			}
			w.recordAdmissionBaseline(evt, snap, res)
			if blocked {
				if res.Verdict != VerdictRejected && res.Verdict != VerdictBlocked {
					t.Fatalf("verdict=%s, want a rejection", res.Verdict)
				}
				if _, err := os.Lstat(link); !os.IsNotExist(err) {
					t.Fatalf("linked entry remained after the decision: %v", err)
				}
				entry, err := store.GetActionForConnector("plugin", evt.Name, "")
				if err != nil || entry == nil || entry.Actions.File == "quarantine" || !strings.HasPrefix(entry.Reason, "link removed") {
					t.Fatalf("journal=%+v err=%v", entry, err)
				}
			} else {
				if res.Verdict != VerdictClean && res.Verdict != VerdictAllowed {
					t.Fatalf("verdict=%s reason=%s", res.Verdict, res.Reason)
				}
				if _, err := os.Lstat(link); err != nil {
					t.Fatalf("admitted link missing: %v", err)
				}
			}
			w.rescanTarget(context.Background(), evt, make(map[string]string))
			if scan.calls != 1 {
				t.Fatalf("rescan repeated the decision: %d scans", scan.calls)
			}
			if _, err := os.Stat(filepath.Join(packageRoot, "package.json")); err != nil {
				t.Fatalf("managed package changed: %v", err)
			}
		})
	}
}
