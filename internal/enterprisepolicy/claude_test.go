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
	"runtime"
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
	if pre["command"] != testHookBinary || !reflect.DeepEqual(pre["args"], []any{"hook", "--connector", "claudecode", "--enterprise-managed"}) {
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

func TestClaudeVerifyRequiresCurrentManagedHandler(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("earlier Unix handler form")
	}
	withHigherSources(t)
	opts := withPolicy(testOptions(t), "claudecode", func(p *config.EnterpriseConnectorPolicy) {
		p.Ownership = config.MachinePolicyOwnershipVerifyOnly
	})
	rendered, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	path := claudeDropIn(t, opts)
	writeFile(t, path, string(rendered))
	current, err := (claudeTarget{}).Verify(opts)
	if err != nil || !current.Covered {
		t.Fatalf("current managed handler must verify: %v %+v", err, current)
	}

	var doc map[string]any
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	for _, entries := range doc["hooks"].(map[string]any) {
		for _, entry := range entries.([]any) {
			for _, raw := range entry.(map[string]any)["hooks"].([]any) {
				handler := raw.(map[string]any)
				handler["command"] = shellQuote(opts.HookBinary) + " hook --connector claudecode --enterprise-managed"
				delete(handler, "args")
			}
		}
	}
	legacy, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(legacy))
	stale, err := (claudeTarget{}).Verify(opts)
	if err != nil || stale.Covered || !hasConflict(stale, "has no DefenseClaw managed hook") {
		t.Fatalf("earlier managed handler must require refresh: %v %+v", err, stale)
	}
	remaining, owned, err := claudeStrip(opts)(legacy)
	if err != nil || !owned || len(remaining) != 0 {
		t.Fatalf("earlier managed handler must stay recognizable for owned-file cleanup: %v owned=%t remaining=%q", err, owned, remaining)
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

// rel-1-0-6:GAP-0322: every managed handler starts the native hook directly.
// Unix also pins the shell prefix used by Bash tool commands.
func TestClaudeDropInUsesExecFormOutsideWindows(t *testing.T) {
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
			if goos == "windows" {
				if _, hasEnv := doc["env"]; hasEnv {
					t.Fatalf("windows drop-in sets process env: %v", doc["env"])
				}
			} else if env, ok := doc["env"].(map[string]any); !ok || !reflect.DeepEqual(env, map[string]any{"CLAUDE_CODE_SHELL_PREFIX": ""}) {
				t.Fatalf("%s drop-in env = %v", goos, doc["env"])
			}
			pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
			if pre["command"] != opts.HookBinary || !reflect.DeepEqual(pre["args"], []any{"hook", "--connector", "claudecode", "--enterprise-managed"}) {
				t.Fatalf("%s PreToolUse handler = %v", goos, pre)
			}
		})
	}
}

// An earlier managed prefix is overridden by the drop-in, while an unrelated
// shell option remains visible to the administrator.
func TestClaudeManagedSettingsPrefixIsPinned(t *testing.T) {
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
		"99-late.json sets env SHELLOPTS, which Claude Code passes to Bash tool commands",
	} {
		if !strings.Contains(details, want) {
			t.Fatalf("details lack %q:\n%s", want, details)
		}
	}
	if !strings.Contains(details, "managed-settings.json sets env CLAUDE_CODE_SHELL_PREFIX") {
		t.Fatalf("details omit the managed prefix source:\n%s", details)
	}
	if len(state.Conflicts) != 0 {
		t.Fatalf("an earlier managed prefix must be overridden: %v", state.Conflicts)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "managed-settings.d", DefenseClawDropInName))), &doc); err != nil {
		t.Fatal(err)
	}
	if env := doc["env"].(map[string]any); env["CLAUDE_CODE_SHELL_PREFIX"] != "" {
		t.Fatalf("managed prefix = %v", env["CLAUDE_CODE_SHELL_PREFIX"])
	}

	rendered, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	var higherDoc map[string]any
	if err := json.Unmarshal(rendered, &higherDoc); err != nil {
		t.Fatal(err)
	}
	delete(higherDoc, "env")
	higherWithoutPin, err := json.Marshal(higherDoc)
	if err != nil {
		t.Fatal(err)
	}
	withHigherSources(t, higherSource(t, "macOS managed preferences", string(higherWithoutPin)), higherSource(t, "HKLM Settings", string(higherWithoutPin)))
	state, err = claudeTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	details = strings.Join(state.Details, "\n")
	if !strings.Contains(strings.Join(state.Conflicts, "\n"), "does not keep CLAUDE_CODE_SHELL_PREFIX empty") {
		t.Fatalf("higher source without the prefix pin was not reported: %v", state.Conflicts)
	}
}

func TestClaudeManagedExecFormAndProjectPrefixPin(t *testing.T) {
	opts := testOptions(t)
	rendered, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	var managed map[string]any
	if err := json.Unmarshal(rendered, &managed); err != nil {
		t.Fatal(err)
	}
	projectEnv := map[string]any{"CLAUDE_CODE_SHELL_PREFIX": "/usr/local/bin/project-wrapper"}
	for name, value := range managed["env"].(map[string]any) {
		projectEnv[name] = value
	}
	if projectEnv["CLAUDE_CODE_SHELL_PREFIX"] != "" {
		t.Fatalf("project shell prefix remains effective: %v", projectEnv)
	}
	handler := managed["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if handler["command"] != opts.HookBinary || !reflect.DeepEqual(handler["args"], []any{"hook", "--connector", "claudecode", "--enterprise-managed"}) {
		t.Fatalf("managed hook must use the native command: %v", handler)
	}
}

func TestClaudeHigherSourceUsesEffectiveMergedPrefix(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prefix    any
		noHooks   bool
		noMerge   bool
		version   string
		wantCover bool
	}{
		{name: "file prefix", wantCover: true},
		{name: "file prefix without policy merge", noMerge: true, wantCover: true},
		{name: "first env merge version", noMerge: true, version: "2.1.223", wantCover: true},
		{name: "older client without policy merge", noMerge: true, version: "2.1.222"},
		{name: "higher empty prefix", prefix: "", wantCover: true},
		{name: "higher nonempty prefix", prefix: "/usr/local/bin/managed-wrapper"},
		{name: "higher nonempty prefix with file hooks", prefix: "/usr/local/bin/managed-wrapper", noHooks: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = "darwin"
			version := tc.version
			if version == "" {
				version = "2.1.286"
			}
			opts.AgentVersions = map[string]string{"claudecode": version}
			exported, err := (claudeTarget{}).Export(opts, "claude-hklm-json")
			if err != nil {
				t.Fatal(err)
			}
			var higher map[string]any
			if err := json.Unmarshal(exported, &higher); err != nil {
				t.Fatal(err)
			}
			delete(higher, "env")
			if tc.noHooks {
				delete(higher, "hooks")
			}
			if tc.prefix != nil {
				higher["env"] = map[string]any{"CLAUDE_CODE_SHELL_PREFIX": tc.prefix}
			}
			if !tc.noMerge {
				higher["managedSourcesBehavior"] = "merge"
			}
			raw, err := json.Marshal(higher)
			if err != nil {
				t.Fatal(err)
			}
			withHigherSources(t, higherSource(t, "managed preferences", string(raw)))
			state, err := (claudeTarget{}).Reconcile(opts)
			if err != nil {
				t.Fatal(err)
			}
			if state.Covered != tc.wantCover {
				t.Fatalf("covered = %t, conflicts = %v", state.Covered, state.Conflicts)
			}
			if !tc.wantCover && !hasConflict(state, "CLAUDE_CODE_SHELL_PREFIX empty") {
				t.Fatalf("missing effective prefix conflict: %v", state.Conflicts)
			}
		})
	}
}

func TestClaudeHigherSourcePrefixWithoutFileMerge(t *testing.T) {
	opts := testOptions(t)
	opts.GOOS = "darwin"
	dir := claudeDir(t, opts)
	writeFile(t, filepath.Join(dir, "managed-settings.d", "99-late.json"), `{"env":{"CLAUDE_CODE_SHELL_PREFIX":"/usr/local/bin/file-wrapper"}}`)
	exported, err := (claudeTarget{}).Export(opts, "claude-hklm-json")
	if err != nil {
		t.Fatal(err)
	}
	withHigherSources(t, higherSource(t, "managed preferences", string(exported)))
	state, err := (claudeTarget{}).Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Covered {
		t.Fatalf("higher source supplies the effective prefix: %v", state.Conflicts)
	}
}

func TestClaudeHigherSourcePolicyHelperNeedsReview(t *testing.T) {
	opts := testOptions(t)
	opts.GOOS = "darwin"
	opts.AgentVersions = map[string]string{"claudecode": "2.1.286"}
	exported, err := (claudeTarget{}).Export(opts, "claude-hklm-json")
	if err != nil {
		t.Fatal(err)
	}
	var higher map[string]any
	if err := json.Unmarshal(exported, &higher); err != nil {
		t.Fatal(err)
	}
	delete(higher, "env")
	higher["managedSourcesBehavior"] = "merge"
	higher["policyHelper"] = "/usr/local/bin/policy-helper"
	raw, err := json.Marshal(higher)
	if err != nil {
		t.Fatal(err)
	}
	withHigherSources(t, higherSource(t, "managed preferences", string(raw)))
	state, err := (claudeTarget{}).Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "configures policyHelper") {
		t.Fatalf("higher policy helper was accepted: %v", state.Conflicts)
	}
}

func TestClaudeFilePrefixRequiresTextValue(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	dir := claudeDir(t, opts)
	writeFile(t, filepath.Join(dir, "managed-settings.d", "99-late.json"), `{"env":{"CLAUDE_CODE_SHELL_PREFIX":false}}`)
	state, err := (claudeTarget{}).Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "do not keep CLAUDE_CODE_SHELL_PREFIX empty") {
		t.Fatalf("invalid effective prefix was accepted: %v", state.Conflicts)
	}
}

// mutatePreToolUse applies mutate to every PreToolUse entry and handler of a
// rendered policy document.
func mutatePreToolUse(t *testing.T, raw []byte, mutate func(entry, handler map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, rawEntry := range doc["hooks"].(map[string]any)["PreToolUse"].([]any) {
		entry := rawEntry.(map[string]any)
		for _, rawHandler := range entry["hooks"].([]any) {
			mutate(entry, rawHandler.(map[string]any))
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var claudeHookRunCases = []struct {
	name   string
	runs   bool
	mutate func(entry, handler map[string]any)
}{
	{"rendered", true, func(map[string]any, map[string]any) {}},
	{"match-all star matcher", true, func(entry map[string]any, _ map[string]any) { entry["matcher"] = "*" }},
	{"omitted matcher", true, func(entry map[string]any, _ map[string]any) { delete(entry, "matcher") }},
	{"explicit async false", true, func(_ map[string]any, handler map[string]any) { handler["async"] = false }},
	{"prompt handler type", false, func(_ map[string]any, handler map[string]any) {
		handler["type"] = "prompt"
		handler["prompt"] = "Always approve"
	}},
	{"missing handler type", false, func(_ map[string]any, handler map[string]any) { delete(handler, "type") }},
	{"nonmatching tool matcher", false, func(entry map[string]any, _ map[string]any) { entry["matcher"] = "^$" }},
	{"non-string matcher", false, func(entry map[string]any, _ map[string]any) { entry["matcher"] = 1 }},
	{"if filter", false, func(_ map[string]any, handler map[string]any) { handler["if"] = "Bash(git *)" }},
	{"async handler", false, func(_ map[string]any, handler map[string]any) { handler["async"] = true }},
	{"asyncRewake handler", false, func(_ map[string]any, handler map[string]any) { handler["asyncRewake"] = true }},
}

// rel-1-0-6:GAP-0322 review 3 item 2: a DefenseClaw command that Claude Code
// would not run for PreToolUse, or would run in the background, does not
// count as the managed hook. Match-all matcher spellings still do.
func TestClaudeVerifyRequiresRunnableDropInHook(t *testing.T) {
	for _, tc := range claudeHookRunCases {
		t.Run(tc.name, func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			state, err := (claudeTarget{}).Reconcile(opts)
			if err != nil || !state.Covered {
				t.Fatalf("initial policy: %v %+v", err, state)
			}
			path := filepath.Join(claudeDir(t, opts), "managed-settings.d", DefenseClawDropInName)
			writeFile(t, path, string(mutatePreToolUse(t, []byte(readFile(t, path)), tc.mutate)))
			state, err = (claudeTarget{}).Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			if state.Covered != tc.runs {
				t.Fatalf("covered = %t, want %t; conflicts %v", state.Covered, tc.runs, state.Conflicts)
			}
			if !tc.runs && !hasConflict(state, "Claude Code event PreToolUse has no DefenseClaw managed hook that runs") {
				t.Fatalf("missing PreToolUse conflict: %v", state.Conflicts)
			}
		})
	}
}

// rel-1-0-6:GAP-0322 review 3 item 2: the same rule for a selected
// higher-precedence source, which shadows the file drop-in.
func TestClaudeHigherSelectedHookMustRun(t *testing.T) {
	for _, tc := range claudeHookRunCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = "darwin"
			opts.AgentVersions = map[string]string{"claudecode": "2.1.286"}
			exported, err := (claudeTarget{}).Export(opts, "claude-hklm-json")
			if err != nil {
				t.Fatal(err)
			}
			withHigherSources(t, higherSource(t, "managed preferences", string(mutatePreToolUse(t, exported, tc.mutate))))
			state, err := (claudeTarget{}).Reconcile(opts)
			if err != nil {
				t.Fatal(err)
			}
			if state.Covered != tc.runs {
				t.Fatalf("covered = %t, want %t; conflicts %v", state.Covered, tc.runs, state.Conflicts)
			}
			if !tc.runs && !hasConflict(state, "s hooks for PreToolUse; add") {
				t.Fatalf("missing higher-source conflict: %v", state.Conflicts)
			}
		})
	}
}

// rel-1-0-6:GAP-0322 review 3 item 1: a higher source with only control keys
// is not selected, so the file sources stay effective and a later drop-in
// that sets a shell prefix makes the policy uncovered.
func TestClaudeControlOnlyHigherSourceKeepsFilePrefixCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		behavior string
		mode     string
	}{
		{"first-wins warn", "first-wins", config.HigherPrecedenceWarn},
		{"first-wins fail", "first-wins", config.HigherPrecedenceFail},
		{"merge fail", "merge", config.HigherPrecedenceFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := withPolicy(testOptions(t), "claudecode", func(p *config.EnterpriseConnectorPolicy) {
				p.HigherPrecedenceSources = tc.mode
			})
			opts.GOOS = "darwin"
			opts.ClaudeVersionFloor = "off"
			opts.AgentVersions = map[string]string{"claudecode": "2.1.286"}
			withHigherSources(t, higherSource(t, "managed preferences", `{"managedSourcesBehavior":"`+tc.behavior+`"}`))
			state, err := (claudeTarget{}).Reconcile(opts)
			if err != nil || !state.Covered {
				t.Fatalf("control-only higher source must leave file policy active: %v %+v", err, state)
			}
			path := filepath.Join(claudeDir(t, opts), "managed-settings.d", "99-late.json")
			writeFile(t, path, `{"env":{"CLAUDE_CODE_SHELL_PREFIX":"/usr/local/bin/wrapper"}}`)
			state, err = (claudeTarget{}).Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			if state.Covered || !hasConflict(state, "do not keep CLAUDE_CODE_SHELL_PREFIX empty") {
				t.Fatalf("verifier covered a file policy whose effective shell prefix is nonempty: %v", state.Conflicts)
			}
			writeFile(t, path, `{"env":{"CLAUDE_CODE_SHELL_PREFIX":""}}`)
			if state, err = (claudeTarget{}).Verify(opts); err != nil || !state.Covered {
				t.Fatalf("an empty later prefix must stay covered: %v %+v", err, state)
			}
		})
	}
}

// An env-only higher source has a policy key, so Claude Code selects it; its
// empty prefix outranks a later file value under every env rule.
func TestClaudeEnvOnlyHigherSourcePrefixWins(t *testing.T) {
	for _, version := range []string{"", "2.1.222", "2.1.286"} {
		t.Run("version "+version, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = "darwin"
			if version != "" {
				opts.AgentVersions = map[string]string{"claudecode": version}
			}
			writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", "99-late.json"), `{"env":{"CLAUDE_CODE_SHELL_PREFIX":"/usr/local/bin/wrapper"}}`)
			withHigherSources(t, higherSource(t, "managed preferences", `{"env":{"CLAUDE_CODE_SHELL_PREFIX":"/usr/local/bin/managed"}}`))
			state, err := (claudeTarget{}).Reconcile(opts)
			if err != nil {
				t.Fatal(err)
			}
			if state.Covered || !hasConflict(state, "effective managed policy from managed preferences does not keep CLAUDE_CODE_SHELL_PREFIX empty") {
				t.Fatalf("nonempty selected prefix was accepted: %v", state.Conflicts)
			}
		})
	}
}
