// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-2475: a HIGH plugin added while the gateway is stopped gets the live
// watcher's admission in the startup rescan, so action mode quarantines it.
// A first start (no baselines yet) still only records baselines.
func TestStartupRescanAdmitsPluginAddedWhileStopped(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Plugin.TakeAction = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	writePlugin := func(name string) string {
		t.Helper()
		dir := filepath.Join(pluginDir, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("// "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	high := &countingScanner{name: "plugin-scanner", findings: []scanner.Finding{{
		ID: "f1", RuleID: "PLUGIN-001", Severity: scanner.SeverityHigh, Title: "dynamic code",
	}}}
	start := func() (*InstallWatcher, *[]AdmissionResult) {
		var admitted []AdmissionResult
		w := New(cfg, nil, []string{pluginDir}, store, logger, nil, func(r AdmissionResult) {
			admitted = append(admitted, r)
		})
		w.scannerFactory = func(InstallEvent) scanner.Scanner { return high }
		w.runRescanCycle(context.Background())
		return w, &admitted
	}

	existing := writePlugin("existing")
	if _, admitted := start(); len(*admitted) != 0 {
		t.Fatalf("first start admitted %v, want baselines only", *admitted)
	}
	if _, err := os.Lstat(existing); err != nil {
		t.Fatalf("first start moved a pre-existing plugin: %v", err)
	}

	offline := writePlugin("offl1")
	_, admitted := start()
	if len(*admitted) != 1 || (*admitted)[0].Event.Path != offline ||
		(*admitted)[0].Verdict != VerdictRejected {
		t.Fatalf("restart admitted %#v, want offl1 rejected", *admitted)
	}
	if _, err := os.Lstat(offline); !os.IsNotExist(err) {
		t.Fatalf("plugin added while stopped stayed in place: %v", err)
	}
	if _, err := os.Lstat(existing); err != nil {
		t.Fatalf("restart moved the baselined plugin: %v", err)
	}
}
