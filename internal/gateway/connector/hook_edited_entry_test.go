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
	"context"
	"encoding/json"
	"errors"
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
		"copilot": {script: "copilot-hook.sh", file: "defenseclaw.json", foreign: true,
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
				if variant == "foreign" {
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
