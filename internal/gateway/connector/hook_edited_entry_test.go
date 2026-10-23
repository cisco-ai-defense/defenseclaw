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

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The doctor's Python mirror (cli/defenseclaw/hook_integrity.py,
// edited_hook_script) reads the same golden, so the two cannot drift.
func TestEditedHookCommandGolden(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "hook_edited_commands.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Script  string `json:"script"`
		Command string `json:"command"`
		Edited  bool   `json:"edited"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if got := editedDefenseClawHookCommand(tc.Command, tc.Script); got != tc.Edited {
			t.Errorf("editedDefenseClawHookCommand(%q, %q) = %v, want %v", tc.Command, tc.Script, got, tc.Edited)
		}
	}
}

// The hook guard and the doctor apply one rule to a whole hook config: the
// guard repairs, and the doctor reports, an edited DefenseClaw entry even when
// every other entry is intact (GAP-0906). cli/tests/test_hook_integrity.py
// reads the same golden.
func TestEditedHookEntriesGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	data, err := os.ReadFile(filepath.Join("testdata", "hook_edited_entries.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string `json:"name"`
		Script   string `json:"script"`
		File     string `json:"file"`
		Document string `json:"document"`
		Edited   bool   `json:"edited"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		dataDir := filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw")
		path := filepath.Join(t.TempDir(), tc.File)
		document := strings.ReplaceAll(tc.Document, "{data_dir}", filepath.ToSlash(dataDir))
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeHookConfigFile(path)
		if err != nil {
			t.Fatalf("%s: %v", tc.Name, err)
		}
		if got := hookDocumentHoldsEditedEntry(decoded, dataDir, tc.Script); got != tc.Edited {
			t.Errorf("%s: hookDocumentHoldsEditedEntry = %v, want %v", tc.Name, got, tc.Edited)
		}
	}
}

// GAP-0906, GAP-0907: after a DefenseClaw hook entry's script name, hook
// directory or data directory is edited, the Setup repair (which the hook
// guard and the managed guardian run) leaves exactly one hook set and no
// edited entry, uninstall leaves no entry, and look-alike third-party hooks
// outside .defenseclaw are kept. The plugin connectors restore their file.
func TestEditedHookEntriesReplacedAndRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	type hookCase struct {
		script   string
		file     string
		seed     string
		foreign  bool
		owned    bool // DefenseClaw's own file: Setup keeps only its render on a bound event
		install  func(t *testing.T, root, path string) error
		teardown func(t *testing.T, root, path string) error
	}
	hookScript := func(root, script string) string { return filepath.Join(root, ".defenseclaw", "hooks", script) }
	baseOpts := func(root string) SetupOpts {
		return SetupOpts{
			DataDir:       filepath.Join(root, ".defenseclaw"),
			ProxyAddr:     "127.0.0.1:4000",
			APIAddr:       "127.0.0.1:18970",
			APIToken:      "api-token",
			OTLPPathToken: strings.Repeat("a", 64),
		}
	}
	claude := NewClaudeCodeConnector()
	codex := NewCodexConnector()
	cases := map[string]hookCase{
		"claudecode": {script: "claude-code-hook.sh", file: "settings.json",
			install: func(t *testing.T, root, path string) error {
				ClaudeCodeSettingsPathOverride = path
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })
				return claude.Setup(context.Background(), baseOpts(root))
			},
			teardown: func(t *testing.T, root, path string) error {
				return claude.Teardown(context.Background(), baseOpts(root))
			},
		},
		"codex": {script: "codex-hook.sh", file: "config.toml", foreign: true,
			install: func(t *testing.T, root, path string) error {
				CodexConfigPathOverride = path
				t.Cleanup(func() { CodexConfigPathOverride = "" })
				return codex.Setup(context.Background(), baseOpts(root))
			},
			teardown: func(t *testing.T, root, path string) error {
				return codex.Teardown(context.Background(), baseOpts(root))
			},
		},
		"copilot": {script: "copilot-hook.sh", file: "defenseclaw.json", foreign: true, owned: true,
			install: func(t *testing.T, root, path string) error {
				return patchCopilotHooks(path, hookScript(root, "copilot-hook.sh"))
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeCopilotHookReferences(path, hookScript(root, "copilot-hook.sh"))
			},
		},
		"cursor": {script: "cursor-hook.sh", file: "hooks.json", foreign: true,
			install: func(t *testing.T, root, path string) error {
				return patchCursorHooks(path, hookScript(root, "cursor-hook.sh"), "", false)
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeJSONHookReferences(path, cursorOwnedHookCommands(baseOpts(root))...)
			},
		},
		"devin": {script: "devin-hook.sh", file: "hooks.v1.json", foreign: true,
			install: func(t *testing.T, root, path string) error {
				return patchDevinHooks(path, hookScript(root, "devin-hook.sh"))
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeDevinHookReferences(path, hookScript(root, "devin-hook.sh"))
			},
		},
		"kiro-agent": {script: "kiro-hook.sh", file: "defenseclaw.json", foreign: true,
			install: func(t *testing.T, root, path string) error {
				return patchKiroV2AgentHooks(path, hookScript(root, "kiro-hook.sh"))
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeKiroV2AgentHooks(path, hookScript(root, "kiro-hook.sh"))
			},
		},
		"kiro-universal": {script: "kiro-hook.sh", file: "universal.json", seed: `{"hooks": []}`, foreign: true,
			install: func(t *testing.T, root, path string) error {
				return patchKiroV2AgentHooks(path, hookScript(root, "kiro-hook.sh"))
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeKiroV2AgentHooks(path, hookScript(root, "kiro-hook.sh"))
			},
		},
		"kiro-v3": {script: "kiro-hook.sh", file: "hooks.json",
			install: func(t *testing.T, root, path string) error {
				return patchKiroV3Hooks(path, hookScript(root, "kiro-hook.sh"))
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeKiroV3Hooks(path, hookScript(root, "kiro-hook.sh"))
			},
		},
		"hermes": {script: "hermes-hook.sh", file: "config.yaml", foreign: true,
			install: func(t *testing.T, root, path string) error {
				return patchHermesHooks(path, hookScript(root, "hermes-hook.sh"), "")
			},
			teardown: func(t *testing.T, root, path string) error {
				return removeHermesHooks(path, hookScript(root, "hermes-hook.sh"), nil)
			},
		},
	}
	for name, tc := range cases {
		stem := strings.TrimSuffix(tc.script, ".sh")
		variants := map[string][2]string{
			"script": {"/.defenseclaw/hooks/" + tc.script, "/.defenseclaw/hooks/" + stem + "X.sh"},
			"dir":    {"/.defenseclaw/hooks/" + tc.script, "/.defenseclaw/xhooks/" + tc.script},
			"marker": {"/.defenseclaw/hooks/" + tc.script, "/.defenseclawX/hooks/" + tc.script},
		}
		if tc.foreign {
			variants["foreign"] = [2]string{"/.defenseclaw/hooks/" + tc.script, "/bin/" + stem + "X.sh"}
		}
		// rel-1-0-4 GAP-0600: an old copy of the script in another folder.
		variants["copy"] = [2]string{"/.defenseclaw/hooks/" + tc.script, "/lane/" + tc.script}
		for variant, edit := range variants {
			t.Run(name+"/"+variant, func(t *testing.T) {
				root := testenv.PrivateTempDir(t)
				path := filepath.Join(root, "agent", tc.file)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if tc.seed != "" {
					if err := os.WriteFile(path, []byte(tc.seed), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := tc.install(t, root, path); err != nil {
					t.Fatalf("install: %v", err)
				}
				current := filepath.ToSlash(hookScript(root, tc.script))
				installed := readHookFileForTest(t, path)
				sets := strings.Count(installed, current)
				edited := strings.ReplaceAll(installed, edit[0], edit[1])
				editedPath := filepath.ToSlash(root) + edit[1]
				if variant == "copy" {
					writeOldHookCopyForTest(t, editedPath)
				}
				kept := strings.Count(edited, editedPath)
				if sets == 0 || kept == 0 || strings.Contains(edited, current) {
					t.Fatalf("fixture did not edit every hook entry (%d sets, %d edited):\n%s", sets, kept, edited)
				}
				if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := tc.install(t, root, path); err != nil {
					t.Fatalf("repair: %v", err)
				}
				repaired := readHookFileForTest(t, path)
				if got := strings.Count(repaired, current); got != sets {
					t.Errorf("repair left %d references to the hook script, want %d (one hook set):\n%s", got, sets, repaired)
				}
				wantKept := 0
				if variant == "foreign" && !tc.owned {
					wantKept = kept
				}
				if got := strings.Count(repaired, editedPath); got != wantKept {
					t.Errorf("repair kept %d entries naming %s, want %d:\n%s", got, editedPath, wantKept, repaired)
				}
				if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := tc.teardown(t, root, path); err != nil {
					t.Fatalf("uninstall: %v", err)
				}
				if variant == "foreign" {
					wantKept = kept // teardown removes only DefenseClaw's entries
				}
				left := readHookFileForTest(t, path)
				if got := strings.Count(left, editedPath); got != wantKept || strings.Contains(left, current) {
					t.Errorf("uninstall left %d entries naming %s (want %d) or the hook script:\n%s", got, editedPath, wantKept, left)
				}
			})
		}
	}

	t.Run("plugins", func(t *testing.T) {
		for name, conn := range map[string]Connector{"amp": NewAMPConnector(), "opencode": NewOpenCodeConnector()} {
			root := testenv.PrivateTempDir(t)
			plugin := filepath.Join(root, "plugins", "defenseclaw.js")
			if name == "amp" {
				previous := AMPPluginPathOverride
				AMPPluginPathOverride = plugin
				t.Cleanup(func() { AMPPluginPathOverride = previous })
			} else {
				previous := OpenCodePluginPathOverride
				OpenCodePluginPathOverride = plugin
				t.Cleanup(func() { OpenCodePluginPathOverride = previous })
			}
			opts := baseOpts(root)
			if name == "amp" {
				opts = prepareAmpSetupOptsForTest(t, opts)
			} else {
				opts = prepareOpenCodeSetupOptsForTest(t, opts)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("%s Setup: %v", name, err)
			}
			pristine := readHookFileForTest(t, plugin)
			if err := os.WriteFile(plugin, []byte("// edited\n"+pristine), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("%s repair: %v", name, err)
			}
			if got := readHookFileForTest(t, plugin); got != pristine {
				t.Errorf("%s repair did not restore the edited plugin", name)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("%s Teardown: %v", name, err)
			}
			if _, err := os.Stat(plugin); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s Teardown left the plugin: %v", name, err)
			}
		}
	})
}

func readHookFileForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// GAP-0906: editing, deleting or duplicating ONE DefenseClaw hook entry left
// the others matching, so the presence check the hook guard, the managed
// guardian and Setup verification share still passed (Hermes and Copilot
// matched any one owned command) and the edited event ran unguarded until
// the next gateway restart. Every connector must report a single edited
// entry absent, and Setup must restore the exact render: byte-identical,
// same mode, written by rename, with the user's own hooks and comments kept.
func TestOwnedHooksPresentRejectsSingleEditedEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	base := func(t *testing.T) SetupOpts {
		return SetupOpts{
			DataDir:      filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw"),
			APIAddr:      "127.0.0.1:18970",
			APIToken:     "tok-test",
			WorkspaceDir: t.TempDir(),
		}
	}
	override := func(t *testing.T, target *string, value string) {
		previous := *target
		*target = value
		t.Cleanup(func() { *target = previous })
	}
	cases := map[string]struct {
		script  string
		install func(t *testing.T) (Connector, SetupOpts)
	}{
		"hermes": {"hermes-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			// The operator's comment and settings outside hooks must survive.
			if err := os.WriteFile(path, []byte("# operator comment\nmodel: test-model\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			override(t, &HermesConfigPathOverride, path)
			return NewHermesConnector(), prepareHermesSetupAdmissionFixture(t, base(t))
		}},
		"copilot": {"copilot-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			override(t, &CopilotHooksPathOverride, filepath.Join(t.TempDir(), "defenseclaw.json"))
			return NewCopilotConnector(), base(t)
		}},
		"antigravity": {"antigravity-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			override(t, &AntigravityHooksPathOverride, filepath.Join(t.TempDir(), "hooks.json"))
			return NewAntigravityConnector(), base(t)
		}},
		"cursor": {"cursor-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			override(t, &CursorHooksPathOverride, filepath.Join(t.TempDir(), "hooks.json"))
			return NewCursorConnector(), base(t)
		}},
		"devin": {"devin-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			opts := base(t)
			opts.ConfigHome = t.TempDir()
			return NewDevinConnector(), opts
		}},
		"codex": {"codex-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			override(t, &CodexConfigPathOverride, filepath.Join(t.TempDir(), "config.toml"))
			return NewCodexConnector(), base(t)
		}},
		"kiro": {"kiro-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			override(t, &KiroHomeOverride, t.TempDir())
			return NewKiroConnector(), base(t)
		}},
		"claudecode": {"claude-code-hook.sh", func(t *testing.T) (Connector, SetupOpts) {
			override(t, &ClaudeCodeSettingsPathOverride, filepath.Join(t.TempDir(), "settings.json"))
			override(t, &ClaudeCodeManagedSettingsRootOverride, t.TempDir())
			return NewClaudeCodeConnector(), base(t)
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			conn, opts := tc.install(t)
			ctx := context.Background()
			if err := conn.Setup(ctx, opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			current := "/hooks/" + tc.script
			edits := map[string]string{
				"dir":    "/xhooks/" + tc.script,
				"script": "/hooks/" + strings.TrimSuffix(tc.script, ".sh") + "X.sh",
			}
			// expectRepaired writes a tampered file, requires the presence
			// check to fail, runs the Setup repair and requires the render.
			expectRepaired := func(t *testing.T, path, label string, pristine, tampered []byte) {
				t.Helper()
				if err := os.WriteFile(path, tampered, 0o600); err != nil {
					t.Fatal(err)
				}
				before, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
					t.Fatalf("%s: OwnedHooksPresent = %v, %v; want false", label, present, err)
				}
				if err := conn.Setup(ctx, opts); err != nil {
					t.Fatalf("%s: repair: %v", label, err)
				}
				after, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := readHookFileForTest(t, path); got != string(pristine) {
					t.Fatalf("%s: repair is not the Setup render:\n%s", label, got)
				}
				if after.Mode().Perm() != 0o600 || os.SameFile(before, after) {
					t.Fatalf("%s: repair mode %v, replaced by rename %v", label, after.Mode().Perm(), !os.SameFile(before, after))
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
					t.Fatalf("%s: OwnedHooksPresent after repair = %v, %v", label, present, err)
				}
			}
			checked := 0
			for _, path := range HookConfigPathsForConnector(conn, opts) {
				pristine, err := os.ReadFile(path)
				if err != nil || !bytes.Contains(pristine, []byte(current)) {
					continue
				}
				checked++
				for i := range bytes.Count(pristine, []byte(current)) {
					for variant, edit := range edits {
						label := fmt.Sprintf("%s entry %d %s", filepath.Base(path), i, variant)
						expectRepaired(t, path, label, pristine, replaceNthForTest(pristine, current, edit, i))
					}
				}
				if filepath.Ext(path) != ".toml" { // Codex refuses two handlers in one group by design.
					// An edited copy beside the working entry fails every call too.
					document := decodeHookFileForTest(t, path)
					if !insertEditedHookCopyForTest(document, current, edits["dir"]) {
						t.Fatal("no hook handler to copy")
					}
					expectRepaired(t, path, "edited copy", pristine, encodeHookFileForTest(t, path, document))
				}
				// rel-1-0-4 GAP-0600: an entry repointed at an old copy of
				// the script in another folder, alone or beside the working
				// entry, and then with that copy deleted.
				registered := filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", tc.script))
				lane := filepath.ToSlash(filepath.Join(testenv.PrivateTempDir(t), "lane", tc.script))
				if !bytes.Contains(pristine, []byte(registered)) {
					t.Fatalf("%s does not name %s", path, registered)
				}
				writeOldHookCopyForTest(t, lane)
				repointed := replaceNthForTest(pristine, registered, lane, 0)
				expectRepaired(t, path, "repointed at a copy", pristine, repointed)
				if filepath.Ext(path) != ".toml" {
					document := decodeHookFileForTest(t, path)
					if !insertEditedHookCopyForTest(document, registered, lane) {
						t.Fatal("no hook handler to copy")
					}
					expectRepaired(t, path, "copy beside", pristine, encodeHookFileForTest(t, path, document))
				}
				if err := os.Remove(lane); err != nil {
					t.Fatal(err)
				}
				// Without DefenseClaw's --event binding nothing marks a
				// deleted copy as DefenseClaw's; a user's own hook of that
				// name is kept.
				if bytes.Contains(repointed, []byte(lane+" --")) || bytes.Contains(repointed, []byte(lane+"' --")) {
					expectRepaired(t, path, "repointed at a deleted copy", pristine, repointed)
				}
				// A shell wrapper in front of an old copy runs it too.
				writeOldHookCopyForTest(t, lane)
				wrapped := pristine
				// The command word as JSON, YAML ('' is a quote) or TOML
				// writes it, quoted for the shell or not.
				for _, quote := range [][2]string{{`"'`, `"bash '`}, {`'''`, `'bash ''`}, {`"`, `"bash `}, {`'`, `'bash `}} {
					if bytes.Contains(pristine, []byte(quote[0]+registered)) {
						wrapped = replaceNthForTest(pristine, quote[0]+registered, quote[1]+lane, 0)
						break
					}
				}
				if bytes.Equal(wrapped, pristine) {
					t.Fatalf("%s: no command word to wrap", path)
				}
				expectRepaired(t, path, "wrapped copy", pristine, wrapped)
				if name != "hermes" && name != "copilot" {
					continue
				}
				document := decodeHookFileForTest(t, path)
				hooks := document["hooks"].(map[string]interface{})
				event, userHook := "agentStop", map[string]interface{}{"type": "command", "bash": "/usr/local/bin/audit-stop.sh"}
				if name == "hermes" {
					event, userHook = "pre_tool_call", map[string]interface{}{"command": "/usr/local/bin/audit-tool.sh"}
				}
				ours := hooks[event].([]interface{})[0]
				hooks[event] = []interface{}{userHook, ours}
				withUser := encodeHookFileForTest(t, path, document)
				if name == "copilot" {
					// defenseclaw.json is DefenseClaw's file: on an event it
					// binds, another hook is not kept (rel-1-0-4 GAP-0600).
					expectRepaired(t, path, "another hook on a bound event", pristine, withUser)
					continue
				}
				// The user's own hook is ignored, then kept by every repair.
				if err := os.WriteFile(path, withUser, 0o600); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
					t.Fatalf("the user's own hook made the registration absent: %v, %v", present, err)
				}
				hooks[event] = []interface{}{userHook}
				expectRepaired(t, path, "deleted entry", withUser, encodeHookFileForTest(t, path, document))
				hooks[event] = []interface{}{userHook, ours, ours}
				expectRepaired(t, path, "duplicate entry", withUser, encodeHookFileForTest(t, path, document))
				if name == "hermes" && !bytes.HasPrefix(withUser, []byte("# operator comment\nmodel: test-model\n")) {
					t.Fatalf("Setup rewrote the operator's lines:\n%s", withUser)
				}
			}
			if checked == 0 {
				t.Fatal("no hook config file references the hook script")
			}
		})
	}
}

// writeOldHookCopyForTest writes an earlier release's generated hook script
// (its marker line, no check of the call) at path.
func writeOldHookCopyForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/bash\n# defenseclaw-managed-hook v6\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func replaceNthForTest(data []byte, old, replacement string, n int) []byte {
	offset := 0
	for range n {
		offset += bytes.Index(data[offset:], []byte(old)) + len(old)
	}
	index := offset + bytes.Index(data[offset:], []byte(old))
	return append(append(append([]byte(nil), data[:index]...), replacement...), data[index+len(old):]...)
}

// insertEditedHookCopyForTest inserts into document, after the first hook
// handler that runs current, a copy of it that runs edited instead.
func insertEditedHookCopyForTest(document map[string]interface{}, current, edited string) bool {
	var insert func(raw interface{}) (interface{}, bool)
	insert = func(raw interface{}) (interface{}, bool) {
		switch value := raw.(type) {
		case map[string]interface{}:
			for key, item := range value {
				if updated, ok := insert(item); ok {
					value[key] = updated
					return value, true
				}
			}
		case []interface{}:
			for i, item := range value {
				entry, isMap := item.(map[string]interface{})
				data, _ := json.Marshal(entry)
				if _, group := entry["hooks"]; isMap && !group && bytes.Contains(data, []byte(current)) {
					var copied interface{}
					decoder := json.NewDecoder(bytes.NewReader(bytes.ReplaceAll(data, []byte(current), []byte(edited))))
					decoder.UseNumber()
					if decoder.Decode(&copied) != nil {
						return raw, false
					}
					out := append(append(append([]interface{}{}, value[:i+1]...), copied), value[i+1:]...)
					return out, true
				}
				if updated, ok := insert(item); ok {
					value[i] = updated
					return value, true
				}
			}
		}
		return raw, false
	}
	_, ok := insert(document)
	return ok
}

func decodeHookFileForTest(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	if filepath.Ext(path) == ".yaml" {
		document, err := readYAMLObject(path)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	document, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// encodeHookFileForTest renders document the way Setup writes the file.
func encodeHookFileForTest(t *testing.T, path string, document map[string]interface{}) []byte {
	t.Helper()
	if filepath.Ext(path) == ".yaml" {
		data, err := marshalTopLevelYAMLFieldPreservingOtherBytes(path, "hooks", document["hooks"])
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// rel-1-0-4 GAP-0600: in DefenseClaw's own hook file (Copilot's and Kiro's
// defenseclaw.json) an entry beside DefenseClaw's on a bound event ran a
// hook DefenseClaw does not keep current while the presence check passed: a
// shell or env wrapper around an old copy, a renamed copy, or a copy without
// the generated-hook marker. Presence fails and Setup leaves its render alone.
func TestOwnedHookFileHoldsOnlyTheSetupRender(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	override := func(t *testing.T, target *string, value string) {
		previous := *target
		*target = value
		t.Cleanup(func() { *target = previous })
	}
	cases := map[string]struct {
		install func(t *testing.T) Connector
		beside  func(document map[string]interface{}, command string)
	}{
		"copilot": {
			install: func(t *testing.T) Connector {
				override(t, &CopilotHooksPathOverride, filepath.Join(t.TempDir(), "defenseclaw.json"))
				return NewCopilotConnector()
			},
			beside: func(document map[string]interface{}, command string) {
				hooks := document["hooks"].(map[string]interface{})
				hooks["preToolUse"] = append(hooks["preToolUse"].([]interface{}),
					map[string]interface{}{"type": "command", "bash": command, "timeoutSec": 30})
			},
		},
		"kiro": {
			install: func(t *testing.T) Connector {
				override(t, &KiroHomeOverride, t.TempDir())
				return NewKiroConnector()
			},
			beside: func(document map[string]interface{}, command string) {
				document["hooks"] = append(document["hooks"].([]interface{}), map[string]interface{}{
					"name": "audit", "trigger": "PreToolUse", "matcher": ".*", "timeout": 30, "enabled": true,
					"action": map[string]interface{}{"type": "command", "command": command},
				})
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			conn := tc.install(t)
			opts := SetupOpts{
				DataDir:  filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw"),
				APIAddr:  "127.0.0.1:18970",
				APIToken: "tok-test",
			}
			ctx := context.Background()
			if err := conn.Setup(ctx, opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			paths := HookConfigPathsForConnector(conn, opts)
			if len(paths) == 0 || filepath.Base(paths[0]) != "defenseclaw.json" {
				t.Fatalf("hook config paths = %v", paths)
			}
			path := paths[0]
			pristine, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lane := filepath.Join(testenv.PrivateTempDir(t), "lane")
			copied := filepath.Join(lane, name+"-hook.sh")
			writeOldHookCopyForTest(t, copied)
			renamed := filepath.Join(lane, "old.sh")
			stripped := filepath.Join(lane, "stripped", name+"-hook.sh")
			for _, unmarked := range []string{renamed, stripped} {
				if err := os.MkdirAll(filepath.Dir(unmarked), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(unmarked, []byte("#!/bin/bash\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for label, command := range map[string]string{
				"bash wrapper":         "/bin/bash " + copied + " --event preToolUse",
				"bare bash wrapper":    "bash " + copied,
				"env wrapper":          "/usr/bin/env " + copied,
				"renamed copy":         renamed + " --event preToolUse",
				"marker-stripped copy": stripped,
			} {
				document := decodeHookFileForTest(t, path)
				tc.beside(document, command)
				if err := os.WriteFile(path, encodeHookFileForTest(t, path, document), 0o600); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
					t.Fatalf("%s: OwnedHooksPresent = %v, %v; want false", label, present, err)
				}
				if err := conn.Setup(ctx, opts); err != nil {
					t.Fatalf("%s: repair: %v", label, err)
				}
				if got := readHookFileForTest(t, path); got != string(pristine) {
					t.Fatalf("%s: repair is not the Setup render:\n%s", label, got)
				}
			}
		})
	}
}

// DefenseClaw's own entry in its own hook file with Setup's command but
// another key (a per-entry env such as BASH_ENV, a cwd, an edited
// description) runs the hook under the user's terms: only Setup's whole
// entry is DefenseClaw's current hook. Presence fails and Setup restores it.
func TestOwnedHookFileEntryIsTheWholeSetupRender(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	override := func(t *testing.T, target *string, value string) {
		previous := *target
		*target = value
		t.Cleanup(func() { *target = previous })
	}
	cases := map[string]struct {
		install func(t *testing.T) Connector
		own     func(document map[string]interface{}) (entry, action map[string]interface{})
	}{
		"copilot": {
			install: func(t *testing.T) Connector {
				override(t, &CopilotHooksPathOverride, filepath.Join(t.TempDir(), "defenseclaw.json"))
				return NewCopilotConnector()
			},
			own: func(document map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
				entry := document["hooks"].(map[string]interface{})["preToolUse"].([]interface{})[0].(map[string]interface{})
				return entry, entry
			},
		},
		"kiro": {
			install: func(t *testing.T) Connector {
				override(t, &KiroHomeOverride, t.TempDir())
				return NewKiroConnector()
			},
			own: func(document map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
				for _, item := range document["hooks"].([]interface{}) {
					if entry := item.(map[string]interface{}); entry["trigger"] == "PreToolUse" {
						return entry, entry["action"].(map[string]interface{})
					}
				}
				return nil, nil
			},
		},
	}
	edits := map[string]func(entry, action map[string]interface{}){
		"env": func(entry, _ map[string]interface{}) {
			entry["env"] = map[string]interface{}{"BASH_ENV": "/tmp/exit-0.sh"}
		},
		"cwd": func(entry, _ map[string]interface{}) { entry["cwd"] = "/tmp" },
		"action env": func(_, action map[string]interface{}) {
			action["env"] = map[string]interface{}{"BASH_ENV": "/tmp/exit-0.sh"}
		},
		"description": func(entry, _ map[string]interface{}) { entry["description"] = "audit" },
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			conn := tc.install(t)
			opts := SetupOpts{
				DataDir:  filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw"),
				APIAddr:  "127.0.0.1:18970",
				APIToken: "tok-test",
			}
			ctx := context.Background()
			if err := conn.Setup(ctx, opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			path := HookConfigPathsForConnector(conn, opts)[0]
			pristine, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("pristine: OwnedHooksPresent = %v, %v; want true", present, err)
			}
			for label, edit := range edits {
				document := decodeHookFileForTest(t, path)
				entry, action := tc.own(document)
				edit(entry, action)
				if err := os.WriteFile(path, encodeHookFileForTest(t, path, document), 0o600); err != nil {
					t.Fatal(err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
					t.Fatalf("%s: OwnedHooksPresent = %v, %v; want false", label, present, err)
				}
				if err := conn.Setup(ctx, opts); err != nil {
					t.Fatalf("%s: repair: %v", label, err)
				}
				if got := readHookFileForTest(t, path); got != string(pristine) {
					t.Fatalf("%s: repair is not the Setup render:\n%s", label, got)
				}
			}
		})
	}
}

func TestCopilotSetupRemovesOwnHandlerFromUnexpectedEvent(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "defenseclaw.json")
			dataDir := t.TempDir()
			script := filepath.Join(dataDir, "hooks", "copilot-hook.sh")
			if goos == "windows" {
				script = windowsCopilotPowerShellAdapterCommand(script)
			}
			command := copilotHookInvocationCommandForEvent(goos, "preToolUse", script)
			field := "bash"
			if goos == "windows" {
				field = "powershell"
			}
			document := map[string]interface{}{
				"hooks": map[string]interface{}{
					"unexpectedEvent": []interface{}{
						map[string]interface{}{"type": "command", field: command},
						map[string]interface{}{"type": "command", field: "echo operator"},
					},
				},
			}
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := patchCopilotHooksForOS(path, script, []string{"preToolUse"}, goos); err != nil {
				t.Fatal(err)
			}
			got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})["unexpectedEvent"]
			want := []interface{}{map[string]interface{}{"type": "command", field: "echo operator"}}
			if !sameHookJSON(got, want) {
				t.Fatalf("unexpected event handlers = %v, want %v", got, want)
			}
			if goos == runtime.GOOS {
				if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, goos); err != nil {
					t.Fatal(err)
				}
				complete := decodeHookFileForTest(t, path)
				complete["hooks"].(map[string]interface{})["unexpectedEvent"] = []interface{}{
					map[string]interface{}{"type": "command", field: command},
				}
				if NewCopilotConnector().renderedHookEntriesPresent(SetupOpts{DataDir: dataDir}, complete) {
					t.Fatal("unexpected DefenseClaw event handler counted as current")
				}
			}
		})
	}
}

func TestCopilotSetupRemovesEditedHandlerFromUnexpectedEvent(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, field := range []string{"command", "bash", "powershell", "command_windows", "commandWindows"} {
			for _, shape := range []string{"prefix", "nested-list", "nested-mapping"} {
				t.Run(goos+"/"+field+"/"+shape, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "defenseclaw.json")
					dataDir := t.TempDir()
					script := filepath.Join(dataDir, "hooks", "copilot-hook.sh")
					if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, goos); err != nil {
						t.Fatal(err)
					}
					command := copilotHookInvocationCommandForEvent(goos, "preToolUse", script)
					var edited interface{} = map[string]interface{}{field: "echo pre; " + command}
					if shape != "prefix" {
						edited = map[string]interface{}{
							"handlers": []interface{}{map[string]interface{}{field: command + "; echo after"}},
						}
					}
					operator := map[string]interface{}{"bash": "echo operator", "note": script}
					document := decodeHookFileForTest(t, path)
					hooks := document["hooks"].(map[string]interface{})
					if shape == "nested-mapping" {
						hooks["unexpectedEvent"] = edited
						hooks["operatorEvent"] = []interface{}{operator}
					} else {
						hooks["unexpectedEvent"] = []interface{}{edited, operator}
					}
					if err := os.WriteFile(path, encodeHookFileForTest(t, path, document), 0o600); err != nil {
						t.Fatal(err)
					}
					present := func() bool {
						hooks := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
						want := make(map[string]interface{}, len(copilotCurrentHookEvents))
						for _, event := range copilotCurrentHookEvents {
							want[event] = copilotHookRegistration(goos, event, script)
						}
						return hookEventEntriesMatch(hooks, want, func(event string, entry interface{}) bool {
							if _, registered := want[event]; registered {
								return true
							}
							return copilotUnexpectedEventOwnsHook(entry, script)
						})
					}
					if present() {
						t.Fatal("edited DefenseClaw handler counted as current before repair")
					}
					if goos == runtime.GOOS && NewCopilotConnector().renderedHookEntriesPresent(
						SetupOpts{DataDir: dataDir}, decodeHookFileForTest(t, path)) {
						t.Fatal("native presence accepted edited DefenseClaw handler")
					}
					if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, goos); err != nil {
						t.Fatal(err)
					}
					got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
					if shape == "nested-mapping" {
						if _, exists := got["unexpectedEvent"]; exists {
							t.Fatalf("Setup kept the edited handler: %v", got["unexpectedEvent"])
						}
						if !sameHookJSON(got["operatorEvent"], []interface{}{operator}) {
							t.Fatalf("Setup changed the operator handler: %v", got["operatorEvent"])
						}
					} else if !sameHookJSON(got["unexpectedEvent"], []interface{}{operator}) {
						t.Fatalf("Setup left the edited handler or changed the operator handler: %v", got["unexpectedEvent"])
					}
					if !present() {
						t.Fatal("repaired Copilot registration is still absent")
					}
					if goos == runtime.GOOS && !NewCopilotConnector().renderedHookEntriesPresent(
						SetupOpts{DataDir: dataDir}, decodeHookFileForTest(t, path)) {
						t.Fatal("native presence still rejects repaired Copilot registration")
					}
				})
			}
		}
	}
}

func TestCopilotSetupRemovesNonListOwnHandlerFromUnexpectedEvent(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "defenseclaw.json")
			dataDir := t.TempDir()
			script := filepath.Join(dataDir, "hooks", "copilot-hook.sh")
			if goos == "windows" {
				script = windowsCopilotPowerShellAdapterCommand(script)
			}
			command := copilotHookInvocationCommandForEvent(goos, "preToolUse", script)
			field := "bash"
			if goos == "windows" {
				field = "powershell"
			}
			own := map[string]interface{}{"type": "command", field: command}
			hooks := map[string]interface{}{
				"unexpectedEvent": own,
				"nestedEvent":     map[string]interface{}{"handlers": []interface{}{own}},
				"operatorEvent":   map[string]interface{}{"type": "command", field: "echo operator"},
			}
			if goos == "windows" {
				hooks["wrappedEvent"] = []interface{}{map[string]interface{}{
					"type": "command", field: command + "; Write-Output x",
				}}
			}
			if err := writeJSONObject(path, map[string]interface{}{"hooks": hooks}); err != nil {
				t.Fatal(err)
			}
			if goos == runtime.GOOS {
				if NewCopilotConnector().renderedHookEntriesPresent(SetupOpts{DataDir: dataDir},
					decodeHookFileForTest(t, path)) {
					t.Fatal("non-list DefenseClaw event handler counted as current")
				}
			}
			if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, goos); err != nil {
				t.Fatal(err)
			}
			got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
			for _, event := range []string{"unexpectedEvent", "nestedEvent", "wrappedEvent"} {
				if _, exists := got[event]; exists {
					t.Errorf("Setup kept DefenseClaw handler on %s: %v", event, got[event])
				}
			}
			if !sameHookJSON(got["operatorEvent"], hooks["operatorEvent"]) {
				t.Errorf("Setup changed operator handler: %v", got["operatorEvent"])
			}
			if goos == runtime.GOOS && !NewCopilotConnector().renderedHookEntriesPresent(
				SetupOpts{DataDir: dataDir}, decodeHookFileForTest(t, path)) {
				t.Error("repaired Copilot registration is still absent")
			}
		})
	}
}

func TestCopilotUnexpectedHandlerSetupAndTeardownAgree(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, shape := range []string{"list", "mapping", "nested"} {
			t.Run(goos+"/"+shape, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "defenseclaw.json")
				script := filepath.Join(root, "hooks", "copilot-hook.sh")
				if goos == "windows" {
					script = windowsCopilotPowerShellAdapterCommand(script)
				}
				command := copilotHookInvocationCommandForEvent(goos, "preToolUse", script)
				field := "bash"
				if goos == "windows" {
					field = "powershell"
				}
				operator := map[string]interface{}{field: "echo operator"}
				inject := func() {
					t.Helper()
					if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, goos); err != nil {
						t.Fatal(err)
					}
					document := decodeHookFileForTest(t, path)
					hooks := document["hooks"].(map[string]interface{})
					owned := map[string]interface{}{field: "echo before; " + command}
					switch shape {
					case "list":
						hooks["unexpectedEvent"] = []interface{}{owned, operator}
					case "mapping":
						hooks["unexpectedEvent"] = owned
					case "nested":
						hooks["unexpectedEvent"] = map[string]interface{}{"handlers": []interface{}{owned}}
					}
					hooks["operatorEvent"] = []interface{}{operator}
					if err := writeJSONObject(path, document); err != nil {
						t.Fatal(err)
					}
				}
				inject()
				if !copilotUnexpectedEventOwnsHook(decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})["unexpectedEvent"], script) {
					t.Fatal("Doctor's unexpected handler is not claimed for repair")
				}
				if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, goos); err != nil {
					t.Fatal(err)
				}
				if got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{}); copilotUnexpectedEventOwnsHook(got["unexpectedEvent"], script) {
					t.Fatalf("Setup left DefenseClaw's unexpected handler: %v", got["unexpectedEvent"])
				}
				inject()
				if err := removeCopilotHookReferencesProfile(path, false, script); err != nil {
					t.Fatal(err)
				}
				got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
				if copilotUnexpectedEventOwnsHook(got["unexpectedEvent"], script) {
					t.Fatalf("teardown left DefenseClaw's unexpected handler: %v", got["unexpectedEvent"])
				}
				if !sameHookJSON(got["operatorEvent"], []interface{}{operator}) {
					t.Fatalf("teardown changed the operator handler: %v", got["operatorEvent"])
				}
			})
		}
	}
}

func TestCopilotWindowsUnexpectedLegacyHandlersConverge(t *testing.T) {
	commands := map[string]string{
		"old-adapter": `& 'C:\Old\hooks\copilot-hook.ps1' -Event 'myEvent'`,
		"old-direct":  `& 'C:\Old\DefenseClaw\defenseclaw-hook.exe' hook --connector copilot`,
		"old-process": `Start-Process -FilePath 'C:\Old\DefenseClaw\defenseclaw-hook.exe' -ArgumentList 'hook --connector copilot' -Wait`,
		"old-argv":    `Start-Process -FilePath 'C:\Old\DefenseClaw\defenseclaw-hook.exe' -ArgumentList 'hook','--connector','copilot' -Wait`,
	}
	for name, command := range commands {
		for _, shape := range []string{"list", "mapping", "nested", "nested-powershell"} {
			t.Run(name+"/"+shape, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "defenseclaw.json")
				script := windowsCopilotPowerShellAdapterCommand(filepath.Join(root, "hooks", "copilot-hook.sh"))
				operator := map[string]interface{}{"type": "command", "powershell": "Write-Output operator"}
				inject := func() {
					t.Helper()
					if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, "windows"); err != nil {
						t.Fatal(err)
					}
					cfg := decodeHookFileForTest(t, path)
					hooks := cfg["hooks"].(map[string]interface{})
					owned := map[string]interface{}{"type": "command", "powershell": command}
					switch shape {
					case "list":
						hooks["extraEvent"] = []interface{}{owned, operator}
					case "mapping":
						hooks["extraEvent"] = owned
					case "nested":
						hooks["extraEvent"] = map[string]interface{}{"handlers": []interface{}{owned}}
					case "nested-powershell":
						hooks["extraEvent"] = map[string]interface{}{"powershell": map[string]interface{}{"handlers": []interface{}{owned}}}
					}
					hooks["operatorEvent"] = []interface{}{operator}
					if err := writeJSONObject(path, cfg); err != nil {
						t.Fatal(err)
					}
				}
				inject()
				if !copilotUnexpectedEventOwnsHook(decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})["extraEvent"], script) {
					t.Fatal("Doctor's stale PowerShell handler is not claimed by Setup")
				}
				if err := patchCopilotHooksForOS(path, script, copilotCurrentHookEvents, "windows"); err != nil {
					t.Fatal(err)
				}
				got := decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
				if copilotUnexpectedEventOwnsHook(got["extraEvent"], script) || !sameHookJSON(got["operatorEvent"], []interface{}{operator}) {
					t.Fatalf("Setup did not repair the stale handler and keep the operator: %v", got)
				}
				if shape == "list" && !sameHookJSON(got["extraEvent"], []interface{}{operator}) {
					t.Fatalf("Setup removed the neighboring operator handler: %v", got)
				}
				inject()
				if err := removeCopilotHookReferencesProfile(path, false, script); err != nil {
					t.Fatal(err)
				}
				got = decodeHookFileForTest(t, path)["hooks"].(map[string]interface{})
				if copilotUnexpectedEventOwnsHook(got["extraEvent"], script) || !sameHookJSON(got["operatorEvent"], []interface{}{operator}) {
					t.Fatalf("teardown left the stale handler or changed the operator: %v", got)
				}
				if shape == "list" && !sameHookJSON(got["extraEvent"], []interface{}{operator}) {
					t.Fatalf("teardown removed the neighboring operator handler: %v", got)
				}
			})
		}
	}
}
