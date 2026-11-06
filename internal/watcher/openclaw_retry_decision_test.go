// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestR109G501BRescanDisabledKeepsDecision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a directory link without elevated privileges")
	}
	for _, blocked := range []bool{false, true} {
		name := "benign"
		if blocked {
			name = "blocked"
		}
		t.Run(name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Gateway.Watcher.Plugin.TakeAction = true
			cfg.Watch.RescanEnabled = false
			root := filepath.Join(t.TempDir(), "extensions")
			plugin := filepath.Join(root, name)
			deps := filepath.Join(plugin, "node_modules")
			host := filepath.Join(t.TempDir(), "openclaw")
			for _, path := range []string{deps, host} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(plugin, "package.json"), []byte(`{"name":"example","version":"1.0.0"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(plugin, "index.js")
			if err := os.WriteFile(source, []byte("export const value = 1;\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(host, filepath.Join(deps, "openclaw")); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			w := New(cfg, nil, []string{root}, store, logger, nil, nil)
			w.SetRootConnectors(map[string]string{root: "openclaw"})
			scan := &countingScanner{name: "plugin-scanner"}
			if blocked {
				scan.findings = []scanner.Finding{{ID: "f1", RuleID: "SRC-EXEC", Severity: scanner.SeverityHigh, Title: "Source finding"}}
			}
			w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
			evt := InstallEvent{Type: InstallPlugin, Name: name, Path: plugin, Connector: "openclaw", Timestamp: time.Now()}
			clock := &fakeClock{now: time.Now()}
			w.state.now = clock.Now
			snap := w.admissionSnapshot(evt)
			if snap != nil {
				t.Fatal("rescan disabled unexpectedly produced a snapshot")
			}
			res := w.runAdmission(context.Background(), evt)
			w.recordAdmissionBaseline(evt, snap, res)
			if scan.calls != 1 {
				t.Fatalf("initial scans=%d", scan.calls)
			}
			clock.advance(admissionRetryFirst)
			w.queueDueIssues()
			w.mu.Lock()
			_, repeated := w.pending[plugin]
			w.mu.Unlock()
			if repeated {
				t.Fatal("unchanged plugin was queued for another decision")
			}
			if !blocked {
				if res.Verdict != VerdictClean && res.Verdict != VerdictAllowed {
					t.Fatalf("benign verdict=%s", res.Verdict)
				}
				if _, err := os.Lstat(plugin); err != nil {
					t.Fatalf("benign plugin missing: %v", err)
				}
				return
			}
			issues, err := ReadAdmissionIssues(cfg.DataDir)
			if err != nil || len(issues) != 1 || issues[0].Kind != AdmissionNotQuarantined {
				t.Fatalf("issues=%+v err=%v", issues, err)
			}
			action, err := store.GetActionForConnector("plugin", name, "")
			if err != nil || action == nil || action.Actions.Install != "block" || action.Actions.Runtime != "disable" {
				t.Fatalf("action=%+v err=%v", action, err)
			}
			if err := os.WriteFile(source, []byte("export const value = 2;\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			clock.advance(admissionRetryFirst)
			w.queueDueIssues()
			w.mu.Lock()
			_, changedQueued := w.pending[plugin]
			w.mu.Unlock()
			if !changedQueued {
				t.Fatal("changed plugin was not queued for a new decision")
			}
		})
	}
}

func TestR109G501BPluginSnapshotCoversBundledTree(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	root := filepath.Join(t.TempDir(), "extensions")
	plugin := filepath.Join(root, "provider")
	dependency := filepath.Join(plugin, "node_modules", "dependency")
	if err := os.MkdirAll(dependency, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(plugin, "package.json"): `{"name":"provider","version":"1.0.0"}`,
		filepath.Join(dependency, "index.js"): "export const value = 1;\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, nil, []string{root}, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "provider", Path: plugin, Connector: "openclaw"}
	before, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := w.snapshotForEvent(evt)
	if err != nil || unchanged.ContentHash != before.ContentHash {
		t.Fatalf("unchanged plugin snapshot changed: %v", err)
	}
	baseline := &audit.SnapshotRow{ContentHash: before.ContentHash, ScanID: "scan-1", ScannerFingerprint: "scanner-1"}
	if rescan, _ := shouldRescan(baseline, unchanged, "scanner-1", true); rescan {
		t.Fatal("unchanged plugin was queued")
	}
	if err := os.WriteFile(filepath.Join(dependency, "index.js"), []byte("export const value = 2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	if rescan, reason := shouldRescan(baseline, after, "scanner-1", true); !rescan || reason != "content-changed" {
		t.Fatalf("bundled dependency change: rescan=%t reason=%s", rescan, reason)
	}
}

func TestR109G501BSecureClientKeepsPluginSnapshotScope(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.DeploymentMode = "managed_enterprise"
	cfg.Enterprise.Profile = "secure_client"
	cfg.Watch.RescanContentGated = true
	root := t.TempDir()
	plugin := filepath.Join(root, "provider")
	dependency := filepath.Join(plugin, "node_modules", "dependency")
	if err := os.MkdirAll(dependency, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dependency, "index.js")
	if err := os.WriteFile(entry, []byte("const value = 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{root}, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "provider", Path: plugin, Connector: "openclaw"}
	before, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("const value = 2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	if before.ContentHash != after.ContentHash {
		t.Fatal("Secure Client changed its dependency-only rescan decision")
	}
}

func TestR109G501BPluginSnapshotRetainsUnreadableEntry(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires local file permissions")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	root := t.TempDir()
	plugin := filepath.Join(root, "provider")
	dependency := filepath.Join(plugin, "node_modules", "dependency")
	if err := os.MkdirAll(dependency, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(dependency, "index.js")
	if err := os.WriteFile(entry, []byte("export const value = 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, []string{root}, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "provider", Path: plugin, Connector: "openclaw"}
	if err := os.Chmod(entry, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(entry, 0o600) })
	unreadable, err := w.snapshotForEvent(evt)
	if err != nil || unreadable == nil || unreadable.ContentHash == "" {
		t.Fatalf("unreadable plugin entry has no snapshot: %v", err)
	}
	if err := os.Chmod(entry, 0o600); err != nil {
		t.Fatal(err)
	}
	readable, err := w.snapshotForEvent(evt)
	if err != nil || readable.ContentHash == unreadable.ContentHash {
		t.Fatalf("entry permission repair did not change snapshot: %v", err)
	}
}

func TestR109G501BWatcherPluginPolicy(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.DeploymentMode = "managed_enterprise"
	cfg.Enterprise.Profile = "standalone"
	cfg.Guardrail.RulePack = "strict"
	w := New(cfg, nil, nil, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Connector: "openclaw"}
	plugin, ok := w.scannerFor(evt).(*scanner.PluginScanner)
	if !ok || plugin.Policy != "strict" || plugin.DisableVendorIdentity {
		t.Fatalf("managed strict plugin scanner: %+v", plugin)
	}
	cfg.Guardrail.RulePack = "default"
	plugin = w.scannerFor(evt).(*scanner.PluginScanner)
	if plugin.Policy != "" || plugin.DisableVendorIdentity {
		t.Fatalf("managed default plugin scanner: %+v", plugin)
	}
	cfg.Enterprise.Profile = "secure_client"
	plugin = w.scannerFor(evt).(*scanner.PluginScanner)
	if plugin.Policy != "" || !plugin.DisableVendorIdentity {
		t.Fatalf("Secure Client plugin scanner: %+v", plugin)
	}
}
