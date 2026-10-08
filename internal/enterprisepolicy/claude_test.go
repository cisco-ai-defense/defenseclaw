// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func claudeDir(t *testing.T, opts Options) string {
	t.Helper()
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func withHigherSources(t *testing.T, sources ...higherClaudeSource) {
	t.Helper()
	previous := claudeHigherSources
	claudeHigherSources = func(Options) ([]higherClaudeSource, error) { return sources, nil }
	t.Cleanup(func() { claudeHigherSources = previous })
}

func higherSource(t *testing.T, name, raw string) higherClaudeSource {
	t.Helper()
	doc, err := decodeOrderedObject([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return higherClaudeSource{name: name, doc: doc}
}

func TestClaudeReconcilePublishesLockedDropIn(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	adminSettings := `{"permissions": {"deny": ["Bash(rm -rf /)"]}}` + "\n"
	writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.json"), adminSettings)
	adminDropIn := `{"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "/usr/local/bin/company-audit"}]}]}}` + "\n"
	writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", "10-company.json"), adminDropIn)

	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || state.EffectiveLock != config.ManagedHooksOnlyEnforce || state.ForeignEntries != 1 {
		t.Fatalf("reconcile state: %+v", state)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", DefenseClawDropInName))), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["allowManagedHooksOnly"] != true {
		t.Fatalf("enforce must lock managed hooks: %v", doc)
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if pre["command"] != "'"+testHookBinary+"' hook --connector claudecode --enterprise-managed" {
		t.Fatalf("PreToolUse handler = %v", pre)
	}
	if readFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.json")) != adminSettings ||
		readFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", "10-company.json")) != adminDropIn {
		t.Fatal("administrator managed settings must be untouched byte for byte")
	}
	if again, err := (claudeTarget{}).Reconcile(opts); err != nil || again.Changed {
		t.Fatalf("second reconcile must be a no-op: %v %+v", err, again)
	}
}

func TestClaudeDetectsLaterDropInAndDisableAllHooks(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", "99-late.json"), `{"allowManagedHooksOnly": false}`)
	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "99-late.json sets allowManagedHooksOnly") || state.Covered {
		t.Fatalf("a later drop-in that unlocks hooks must be a conflict: %+v", state.Conflicts)
	}
	writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.json"), `{"disableAllHooks": true}`)
	state, err = claudeTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "disableAllHooks: true") {
		t.Fatalf("managed disableAllHooks must be a conflict: %+v", state.Conflicts)
	}
}

// A company drop-in saved by a Windows editor (UTF-8 BOM, CRLF) is read as
// Claude Code reads it: it was refused, verify failed for every user and the
// error said Claude Code would not start (GAP-0914).
func TestClaudeReadsACompanyDropInWithBOMAndCRLF(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	company := "\ufeff{\r\n  \"permissions\": {\"ask\": [\"Bash(curl:*)\"]}\r\n}\r\n"
	path := filepath.Join(claudeDir(t, opts), "managed-settings.d", "20-company-bom-crlf.json")
	writeFile(t, path, company)
	if _, err := (claudeTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	state, err := claudeTarget{}.Verify(opts)
	if err != nil || !state.Covered {
		t.Fatalf("a BOM+CRLF company drop-in must not break coverage: %v %+v", err, state.Conflicts)
	}
	if readFile(t, path) != company {
		t.Fatal("the company drop-in changed")
	}
}

func TestClaudeHigherPrecedenceSources(t *testing.T) {
	opts := testOptions(t)
	withHigherSources(t, higherSource(t, `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`, `{"model": "opus"}`))
	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.HigherPrecedence) != 1 || !hasConflict(state, "managedSourcesBehavior") || state.Covered {
		t.Fatalf("an HKLM policy without DefenseClaw hooks must block coverage: %+v", state)
	}

	warn := withPolicy(testOptions(t), "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.HigherPrecedenceSources = "warn" })
	state, err = claudeTarget{}.Reconcile(warn)
	if err != nil {
		t.Fatal(err)
	}
	if hasConflict(state, "managedSourcesBehavior") || len(state.HigherPrecedence) != 0 {
		t.Fatalf("warn must downgrade the higher-precedence finding: %+v", state)
	}

	merge := testOptions(t)
	merge.AgentVersions = map[string]string{"claudecode": "2.1.200"}
	withHigherSources(t, higherSource(t, "mdm", `{"managedSourcesBehavior": "merge"}`))
	state, err = claudeTarget{}.Reconcile(merge)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.HigherPrecedence) != 0 || len(state.Pending) != 1 {
		t.Fatalf("merge must compose sources and flag old clients as pending: %+v", state)
	}

	exported, err := claudeTarget{}.Export(testOptions(t), "claude-hklm-json")
	if err != nil {
		t.Fatal(err)
	}
	withHigherSources(t, higherSource(t, "mdm", string(exported)))
	state, err = claudeTarget{}.Verify(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.HigherPrecedence) != 0 {
		t.Fatalf("an MDM source embedding the exported hooks must be accepted: %+v", state)
	}
}

func TestClaudeExportFormats(t *testing.T) {
	opts := testOptions(t)
	for _, format := range []string{"json", "claude-hklm-json", "reg", "plist", "intune-settings-catalog"} {
		data, err := claudeTarget{}.Export(opts, format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		switch format {
		case "claude-hklm-json":
			if strings.Count(strings.TrimSpace(string(data)), "\n") != 0 {
				t.Fatalf("HKLM JSON must be one line")
			}
		case "reg":
			if !strings.Contains(string(data), `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\ClaudeCode]`) {
				t.Fatalf("reg export: %s", data)
			}
		case "plist":
			var anything any
			if err := xml.Unmarshal(data, &anything); err != nil && !strings.Contains(err.Error(), "unknown") {
				t.Fatalf("plist export is not XML: %v", err)
			}
			if !strings.Contains(string(data), "<key>allowManagedHooksOnly</key>") {
				t.Fatalf("plist export: %s", data)
			}
		case "intune-settings-catalog":
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := (claudeTarget{}).Export(opts, "yaml"); err == nil {
		t.Fatal("unknown format must fail")
	}
}

func TestClaudeRemoveDeletesOnlyTheDropIn(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	adminDropIn := filepath.Join(claudeDir(t, opts), "managed-settings.d", "10-company.json")
	writeFile(t, adminDropIn, `{"env": {"X": "1"}}`)
	if _, err := (claudeTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(claudeDir(t, opts), "managed-settings.d", DefenseClawDropInName)); !os.IsNotExist(err) {
		t.Fatalf("drop-in must be removed: %v", err)
	}
	if readFile(t, adminDropIn) != `{"env": {"X": "1"}}` {
		t.Fatal("administrator drop-in must survive removal")
	}
}

func TestClaudeWindowsUsesExecForm(t *testing.T) {
	opts := Options{GOOS: "windows", HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, WindowsProgramFiles: `C:\Program Files`, WindowsProgramData: `C:\ProgramData`}
	data, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"args": [`) || !strings.Contains(string(data), `"--enterprise-managed"`) {
		t.Fatalf("windows drop-in must use the exec form: %s", data)
	}
	path, _ := claudeDropInPath(opts)
	if path != `C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json` {
		t.Fatalf("windows drop-in path = %q", path)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"2.1.242", "2.1.242", 0}, {"2.1.241", "2.1.242", -1}, {"2.2.0 (Claude Code)", "2.1.242", 1}, {"v2.1.300", "2.1.242", 1}} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
