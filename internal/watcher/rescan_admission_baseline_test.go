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

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-2507: a plugin the live watcher admitted gets a rescan baseline that
// carries the admission scan, so later gateway starts skip it while it is
// unchanged instead of re-admitting it and then scanning it again.
func TestLiveAdmissionRecordsRescanBaseline(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	cfg.Watch.RescanContentGated = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	if err := os.MkdirAll(filepath.Join(pluginDir, "existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	medium := &countingScanner{name: "plugin-scanner", findings: []scanner.Finding{{
		ID: "f1", RuleID: "SRC-PY-SUBPROCESS", Severity: scanner.SeverityMedium, Title: "subprocess",
	}}}
	var admitted []AdmissionResult
	start := func() *InstallWatcher {
		w := New(cfg, nil, []string{pluginDir}, store, logger, nil, func(r AdmissionResult) {
			admitted = append(admitted, r)
		})
		w.scannerFactory = func(InstallEvent) scanner.Scanner { return medium }
		w.runRescanCycle(context.Background())
		return w
	}

	w := start()
	live := filepath.Join(pluginDir, "warn8")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "__init__.py"), []byte("import subprocess\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.pending[live] = time.Now().Add(-time.Hour)
	w.processPending(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Path != live || admitted[0].ScanID == "" {
		t.Fatalf("live admission = %#v, want warn8 with a scan id", admitted)
	}
	calls := medium.calls

	for restart := 1; restart <= 2; restart++ {
		start()
		if medium.calls != calls || len(admitted) != 1 {
			t.Fatalf("restart %d scanned %d more times and admitted %d more, want 0",
				restart, medium.calls-calls, len(admitted)-1)
		}
	}
}
