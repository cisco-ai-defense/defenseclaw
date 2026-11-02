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
	"path/filepath"
	"reflect"
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

// An administrator edited DefenseClaw's hook commands (another folder,
// another binary name) and removal restored the edited copy, so every
// Claude Code call ran a missing hook (GAP-1099). Once DefenseClaw published
// the drop-in under its reserved name, the file is DefenseClaw's whatever it
// holds, with or without a repair in between; the administrator's own
// drop-in stays. Codex marks its blocks, so an edited command there goes too.
func TestClaudeRemoveDeletesOnlyTheDropIn(t *testing.T) {
	withHigherSources(t)
	for _, tc := range []struct {
		name, from, to string
		repair         bool
	}{
		{"folder edited then repaired", "/bin/defenseclaw-hook", "/binx/defenseclaw-hook", true},
		{"binary renamed then repaired", "defenseclaw-hook", "defenseclaw-hookX", true},
		{"binary renamed without a repair", "defenseclaw-hook", "defenseclaw-hookX", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			adminDropIn := filepath.Join(claudeDir(t, opts), "managed-settings.d", "10-company.json")
			writeFile(t, adminDropIn, `{"env": {"X": "1"}}`)
			mustReconcile(t, claudeTarget{}, opts)
			dropIn := claudeDropIn(t, opts)
			published := readFile(t, dropIn)
			writeFile(t, dropIn, strings.ReplaceAll(published, tc.from, tc.to))
			if readFile(t, dropIn) == published {
				t.Fatal("test edit did not apply")
			}
			if tc.repair {
				mustReconcile(t, claudeTarget{}, opts)
			}
			mustRemove(t, claudeTarget{}, opts)
			mustNotExist(t, dropIn, "DefenseClaw's drop-in after an edit of its hook commands")
			if readFile(t, adminDropIn) != `{"env": {"X": "1"}}` {
				t.Fatal("administrator drop-in must survive removal")
			}
		})
	}
	t.Run("codex requirements.toml", func(t *testing.T) {
		opts := testOptions(t)
		path := codexPath(t, opts)
		writeFile(t, path, adminCodexRequirements)
		mustReconcile(t, codexTarget{}, opts)
		published := readFile(t, path)
		writeFile(t, path, strings.ReplaceAll(published, "/bin/defenseclaw-hook", "/binx/defenseclaw-hookX"))
		if readFile(t, path) == published {
			t.Fatal("test edit did not apply")
		}
		mustReconcile(t, codexTarget{}, opts)
		mustRemove(t, codexTarget{}, opts)
		if got := readFile(t, path); got != adminCodexRequirements {
			t.Fatalf("removal must leave exactly the administrator text:\n%s", got)
		}
	})
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

// rel-1-0-6:GAP-0322: outside Windows the drop-in's handlers are shell-form
// commands Claude Code starts through /bin/sh with the merged settings env,
// so the drop-in pins the variables that stop or replace them to "" (managed
// env outranks user, project and process values). Windows starts the
// launcher in the exec form and keeps its drop-in unchanged.
func TestClaudeDropInPinsHookShellEnvOutsideWindows(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = goos
			if goos == "windows" {
				opts = Options{GOOS: "windows", HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, WindowsProgramFiles: `C:\Program Files`, WindowsProgramData: `C:\ProgramData`}
			}
			data, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			env, hasEnv := doc["env"].(map[string]any)
			if goos == "windows" {
				if hasEnv {
					t.Fatalf("windows drop-in carries env %v", env)
				}
				return
			}
			// Only what can stop the native hook command and is safe for
			// every process: managed env is process-wide (review finding 4),
			// and a pinned SHELLOPTS broke every script the Bash tool ran
			// (rel-1-0-6:GAP-0465).
			want := map[string]any{"CLAUDE_CODE_SHELL_PREFIX": ""}
			if !reflect.DeepEqual(env, want) {
				t.Fatalf("%s drop-in env = %v, want %v", goos, env, want)
			}
		})
	}
}

// rel-1-0-6:GAP-0322 review finding 4: a pinned name set by another managed
// source is named, before the drop-in (overridden) and after it (applies),
// and a higher-precedence source with the hooks but not the pins is named.
func TestClaudeInspectNamesHookShellEnvOverrides(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	dir := claudeDir(t, opts)
	writeFile(t, filepath.Join(dir, "managed-settings.json"), `{"env": {"CLAUDE_CODE_SHELL_PREFIX": "/usr/local/bin/audit-wrap"}}`+"\n")
	writeFile(t, filepath.Join(dir, "managed-settings.d", "99-late.json"), `{"env": {"SHELLOPTS": "noexec"}}`+"\n")
	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	details := strings.Join(state.Details, "\n")
	for _, want := range []string{
		"managed-settings.json sets env CLAUDE_CODE_SHELL_PREFIX; DefenseClaw's drop-in sets it to \"\" later in merge order",
		"99-late.json sets env SHELLOPTS, which Claude Code passes to the managed hook commands and every Bash tool command",
	} {
		if !strings.Contains(details, want) {
			t.Fatalf("details lack %q:\n%s", want, details)
		}
	}

	rendered, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "env")
	withoutPins, _ := json.Marshal(doc)
	withHigherSources(t, higherSource(t, "macOS managed preferences", string(withoutPins)), higherSource(t, "HKLM Settings", string(rendered)))
	state, err = claudeTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	details = strings.Join(state.Details, "\n")
	if !strings.Contains(details, "macOS managed preferences carries DefenseClaw's hooks but does not set CLAUDE_CODE_SHELL_PREFIX to") {
		t.Fatalf("details lack the unpinned higher source:\n%s", details)
	}
	if strings.Contains(details, "HKLM Settings carries DefenseClaw's hooks but does not set") {
		t.Fatalf("a pinned higher source was reported:\n%s", details)
	}
}
