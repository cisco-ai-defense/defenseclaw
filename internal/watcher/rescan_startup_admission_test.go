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
	"time"

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

// GAP-2475 (verify b14): a user's first plugin, added while the gateway is
// stopped to a root that was empty at the previous start, is admitted too.
func TestStartupRescanAdmitsFirstPluginInEmptyRoot(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Plugin.TakeAction = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	high := &countingScanner{name: "plugin-scanner", findings: []scanner.Finding{{
		ID: "f1", RuleID: "PLUGIN-001", Severity: scanner.SeverityHigh, Title: "dynamic code",
	}}}
	start := func() []AdmissionResult {
		var admitted []AdmissionResult
		w := New(cfg, nil, []string{pluginDir}, store, logger, nil, func(r AdmissionResult) {
			admitted = append(admitted, r)
		})
		w.scannerFactory = func(InstallEvent) scanner.Scanner { return high }
		w.runRescanCycle(context.Background())
		return admitted
	}

	if admitted := start(); len(admitted) != 0 {
		t.Fatalf("first start admitted %v", admitted)
	}
	offline := filepath.Join(pluginDir, "offl1")
	if err := os.MkdirAll(offline, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(offline, "index.js"), []byte("// offl1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admitted := start()
	if len(admitted) != 1 || admitted[0].Event.Path != offline || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("restart admitted %#v, want offl1 rejected", admitted)
	}
	if _, err := os.Lstat(offline); !os.IsNotExist(err) {
		t.Fatalf("first plugin added while stopped stayed in place: %v", err)
	}
}

// GAP-0571: a root that appeared after the gateway started watching (an
// enrolled user created the folder with a plugin in it) is admitted at
// startup, so it is blocked when its scan fails or finds a problem, not
// only baselined.
func TestStartupRescanAdmitsANewRoot(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Plugin.TakeAction = true
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath
	pluginDir := filepath.Join(filepath.Dir(skillDir), "plugins")
	dropped := filepath.Join(pluginDir, "dropped")
	if err := os.MkdirAll(dropped, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropped, "index.js"), []byte("// dropped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var admitted []AdmissionResult
	w := New(cfg, nil, []string{pluginDir}, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "plugin-scanner", findings: []scanner.Finding{{
			ID: "f1", RuleID: "PLUGIN-001", Severity: scanner.SeverityHigh, Title: "dynamic code",
		}}}
	}
	w.AdmitNewRootsAtStartup([]string{pluginDir})
	w.runRescanCycle(context.Background())
	if len(admitted) != 1 || admitted[0].Event.Path != dropped || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("startup rescan admitted %#v, want the plugin in the new root rejected", admitted)
	}
}

// A root absent during one completed gateway run must still be covered by its
// startup marker: a skill placed there while stopped needs install admission.
func TestStartupRescanAdmitsSkillInRootCreatedWhileStopped(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Gateway.Watcher.Skill.TakeAction = true
	absentRoot := filepath.Join(filepath.Dir(skillDir), "later-skills")
	start := func() []AdmissionResult {
		var admitted []AdmissionResult
		w := New(cfg, []string{absentRoot}, nil, store, logger, nil, func(r AdmissionResult) {
			admitted = append(admitted, r)
		})
		w.scannerFactory = func(InstallEvent) scanner.Scanner {
			return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{{
				ID: "f1", RuleID: "SKILL-001", Severity: scanner.SeverityCritical, Title: "critical finding",
			}}}
		}
		w.runRescanCycle(context.Background())
		return admitted
	}
	if admitted := start(); len(admitted) != 0 {
		t.Fatalf("absent root admitted %#v", admitted)
	}
	skill := filepath.Join(absentRoot, "offline")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: offline\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admitted := start()
	if len(admitted) != 1 || admitted[0].Event.Path != skill || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("restart admitted %#v, want offline skill rejected", admitted)
	}
	if _, err := os.Lstat(skill); !os.IsNotExist(err) {
		t.Fatalf("skill created while stopped stayed in place: %v", err)
	}
}

// stoppingScanner stops the watcher during the scan, as a config reload or
// a change of the enrolled users' folders does.
type stoppingScanner struct{ stop context.CancelFunc }

func (s *stoppingScanner) Name() string               { return "skill-scanner" }
func (s *stoppingScanner) Version() string            { return "fake-1" }
func (s *stoppingScanner) SupportedTargets() []string { return []string{"skill"} }
func (s *stoppingScanner) Scan(ctx context.Context, _ string) (*scanner.ScanResult, error) {
	s.stop()
	<-ctx.Done()
	return nil, ctx.Err()
}

// GAP-0980: a skill whose admission the watcher's own stop cut off is
// admitted by the next start, even under a root that start has no baseline
// for, instead of getting a baseline scan whose verdict nothing acts on.
func TestStartupRescanAdmitsSkillWhoseAdmissionWasCutOff(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	cfg.Gateway.Watcher.Skill.TakeAction = true
	skill := filepath.Join(skillDir, "w1-amp-bad")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: w1-amp-bad\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	first := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	first.scannerFactory = func(InstallEvent) scanner.Scanner { return &stoppingScanner{stop: stop} }
	first.pending[skill] = time.Now().Add(-time.Hour)
	first.processPending(ctx)
	first.waitAdmissions()

	var admitted []AdmissionResult
	next := New(cfg, []string{skillDir}, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	next.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "skill-scanner", findings: []scanner.Finding{{
			ID: "f1", RuleID: "SKILL-001", Severity: scanner.SeverityCritical, Title: "critical finding",
		}}}
	}
	next.runRescanCycle(context.Background())
	if len(admitted) != 1 || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("restart admitted %+v, want the cut-off skill rejected", admitted)
	}
	if _, err := os.Lstat(skill); !os.IsNotExist(err) {
		t.Fatalf("cut-off CRITICAL skill stayed in place: %v", err)
	}
}
