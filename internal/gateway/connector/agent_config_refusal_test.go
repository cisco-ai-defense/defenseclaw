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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// GAP-0578: when the agent's own settings turn its hooks off or do not
// parse, Setup refuses before it writes anything, so a gateway start keeps
// the earlier hooks and the user's setting instead of rolling them back.
func TestSetupRefusesAgentSettingsBeforeAnyChange(t *testing.T) {
	cases := []struct {
		name     string
		conn     func() Connector
		settings string
		body     string
		point    func(t *testing.T, path string)
		reason   string
	}{
		{
			name: "codex features hooks false", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "model = \"gpt-5\"\n\n[features]\nhooks = false\n",
			point:  pointCodexConfig,
			reason: "turn them back on with: codex features enable hooks",
		},
		{
			name: "codex retired codex_hooks false", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "[features]\ncodex_hooks = false\n",
			point:  pointCodexConfig,
			reason: "([features] codex_hooks = false)",
		},
		{
			name: "codex config does not parse", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "model = [\n",
			point:  pointCodexConfig,
			reason: "does not parse",
		},
		{
			name: "codex hooks of an unsupported type", conn: func() Connector { return NewCodexConnector() },
			settings: "config.toml", body: "hooks = \"hooks.json\"\n",
			point:  pointCodexConfig,
			reason: "unsupported type",
		},
		{
			name: "claude code disableAllHooks", conn: func() Connector { return NewClaudeCodeConnector() },
			settings: "settings.json", body: `{"disableAllHooks": true}`,
			point: func(t *testing.T, path string) {
				previous := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = path
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
			},
			reason: "remove disableAllHooks",
		},
		{
			name: "copilot disableAllHooks", conn: func() Connector { return NewCopilotConnector() },
			settings: "settings.json", body: `{"disableAllHooks": true}`,
			point:  func(t *testing.T, path string) { t.Setenv("COPILOT_HOME", filepath.Dir(path)) },
			reason: "disableAllHooks=true",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			path := filepath.Join(t.TempDir(), tc.settings)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.point(t, path)
			// Setup's own check, which `defenseclaw setup` asks before it
			// restarts the gateway, refuses the same settings (GAP-0615).
			if err := CheckAgentSettings(tc.conn(), SetupOpts{DataDir: dataDir}); !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("CheckAgentSettings = %v; want the refusal Setup gives, saying %q", err, tc.reason)
			}
			err := tc.conn().Setup(context.Background(), SetupOpts{
				DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok",
			})
			if !errors.Is(err, ErrSetupRefusedUnchanged) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("Setup = %v; want a refusal before any change that says %q", err, tc.reason)
			}
			entries, readErr := os.ReadDir(dataDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				// The lifecycle lock serializes Setup; it is not state.
				if !strings.HasSuffix(entry.Name(), ".lock") {
					t.Errorf("Setup wrote %s into the data dir before refusing", entry.Name())
				}
			}
			if after, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(after, []byte(tc.body)) {
				t.Errorf("Setup changed the agent's settings: %q (%v)", after, readErr)
			}
		})
	}
}

func pointCodexConfig(t *testing.T, path string) {
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = path
	t.Cleanup(func() { CodexConfigPathOverride = previous })
}

// GAP-0615: the check changes nothing and passes settings that let the hooks
// run, and a managed install or a connector without such a refusal is not
// asked.
func TestCheckAgentSettingsPassesUsableSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := []byte("model = \"gpt-5\"\n\n[features]\nhooks = true\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	pointCodexConfig(t, path)
	if err := CheckAgentSettings(NewCodexConnector(), SetupOpts{DataDir: t.TempDir()}); err != nil {
		t.Fatalf("CheckAgentSettings(usable codex config) = %v", err)
	}
	if err := os.WriteFile(path, []byte("[broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAgentSettings(NewCodexConnector(), SetupOpts{DataDir: t.TempDir(), ManagedEnterprise: true}); err != nil {
		t.Fatalf("CheckAgentSettings(managed) = %v; managed requirements decide there", err)
	}
	if err := CheckAgentSettings(NewCursorConnector(), SetupOpts{DataDir: t.TempDir()}); err != nil {
		t.Fatalf("CheckAgentSettings(cursor) = %v; cursor has no agent-settings refusal", err)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != "[broken\n" {
		t.Fatalf("CheckAgentSettings changed the settings: %q (%v)", after, err)
	}
}

// A Claude Code settings file that does not parse cannot show that the
// DefenseClaw hooks are gone. Reporting it clean let a disabled connector's
// failed teardown drop its lock entry and active-set retry while the hooks
// stayed in the file, so fixing the file never removed them (GAP-0578).
func TestClaudeCodeVerifyCleanRefusesSettingsThatDoNotParse(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	prev := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prev })
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}

	hook := filepath.Join(dir, "hooks", "claude-code-hook.sh")
	body := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"` + hook + `"}]}]}}{`
	if err := os.WriteFile(settingsPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewClaudeCodeConnector().VerifyClean(opts); err == nil || !strings.Contains(err.Error(), "is not valid JSON") {
		t.Fatalf("VerifyClean of settings that do not parse = %v, want a not-valid-JSON error", err)
	}

	for _, clean := range []string{"", "  \n", `{"env":{"EDITOR":"vi"}}`} {
		if err := os.WriteFile(settingsPath, []byte(clean), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewClaudeCodeConnector().VerifyClean(opts); err != nil {
			t.Fatalf("VerifyClean of %q = %v, want clean", clean, err)
		}
	}
}

// Setup and the CLI precheck must reject the same unreadable user settings
// before changing the connector or stopping a gateway that serves its peers.
func TestCheckAgentSettingsRefusesUnreadableAndEscapingPaths(t *testing.T) {
	for _, tc := range []struct {
		name, connector, kind, want string
	}{
		{"claude directory", "claudecode", "directory", "not a regular file"},
		{"codex directory", "codex", "directory", "config.toml"},
		{"claude outside link", "claudecode", "outside", "outside your home folder"},
		{"claude dangling link", "claudecode", "dangling", "cannot be followed"},
		{"claude foreign owner link", "claudecode", "foreign owner", "another account owns"},
		{"claude parent link", "claudecode", "parent outside", "outside your home folder"},
		{"codex outside link", "codex", "outside", "leads outside the home"},
		{"codex dangling link", "codex", "dangling", "config.toml"},
		{"codex parent link", "codex", "parent outside", "leads outside the home"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tc.kind != "directory" {
				t.Skip("creating file links requires a Windows privilege")
			}
			home := t.TempDir()
			settingsDir := filepath.Join(home, ".claude")
			filename := "settings.json"
			conn := Connector(NewClaudeCodeConnector())
			if tc.connector == "codex" {
				settingsDir = filepath.Join(home, ".codex")
				filename = "config.toml"
				conn = NewCodexConnector()
			}
			if tc.kind == "parent outside" {
				if err := os.Symlink(t.TempDir(), settingsDir); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(settingsDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(settingsDir, filename)
			switch tc.kind {
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "outside":
				target := filepath.Join(t.TempDir(), filename)
				body := []byte("{}")
				if tc.connector == "codex" {
					body = []byte("model = \"gpt-5\"\n")
				}
				if err := os.WriteFile(target, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "dangling":
				if err := os.Symlink(filepath.Join(home, "missing", filename), path); err != nil {
					t.Fatal(err)
				}
			case "foreign owner":
				target := filepath.Join(home, "other-owned.json")
				if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				previous := pluginGetUID
				pluginGetUID = func() int { return os.Getuid() + 1 }
				t.Cleanup(func() { pluginGetUID = previous })
			}
			if tc.connector == "codex" {
				pointCodexConfig(t, path)
			} else {
				previous := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = path
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
			}
			dataDir := t.TempDir()
			if err := WithUserHomeDir(home, func() error {
				return CheckAgentSettings(conn, SetupOpts{DataDir: dataDir})
			}); !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckAgentSettings = %v; want refusal naming %q", err, tc.want)
			}
		})
	}
}

func TestCheckAgentSettingsAllowsMissingUserSettings(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		conn       Connector
		point      func(*testing.T, string)
	}{
		{"claudecode", ".claude/settings.json", NewClaudeCodeConnector(), func(t *testing.T, path string) {
			previous := ClaudeCodeSettingsPathOverride
			ClaudeCodeSettingsPathOverride = path
			t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
		}},
		{"codex", ".codex/config.toml", NewCodexConnector(), pointCodexConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tc.point(t, filepath.Join(home, tc.file))
			if err := WithUserHomeDir(home, func() error {
				return CheckAgentSettings(tc.conn, SetupOpts{DataDir: t.TempDir()})
			}); err != nil {
				t.Fatalf("missing user settings = %v, want no refusal", err)
			}
		})
	}
}

// The tagged 1.0.2 and 1.0.3 POSIX registration goldens have identical
// Codex and Claude Code settings bytes. Upgrade both supported predecessors
// through user-owned dotfile links without losing the enforcing hooks.
func TestOSSSetupKeepsHooksThroughExternalDotfileLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix dotfile links; Windows path behavior is covered separately")
	}
	for _, tc := range []struct {
		name, connector, linkKind string
	}{
		{"codex config link", "codex", "file"},
		{"codex home link", "codex", "parent"},
		{"claude code settings link", "claudecode", "file"},
		{"claude code home link", "claudecode", "parent"},
	} {
		for _, predecessor := range []string{"1.0.2", "1.0.3"} {
			t.Run(predecessor+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				home := filepath.Join(root, "home")
				outside := filepath.Join(root, "dotfiles")
				if err := os.MkdirAll(home, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(outside, 0o700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", home)
				filename := "config.toml"
				folder := ".codex"
				fixture := "codex.toml"
				conn := Connector(NewCodexConnector())
				if tc.connector == "claudecode" {
					filename, folder, fixture = "settings.json", ".claude", "claudecode.json"
					conn = NewClaudeCodeConnector()
				}
				body, err := os.ReadFile(filepath.Join("testdata", "predecessor_1_0_2_1_0_3", fixture))
				if err != nil {
					t.Fatal(err)
				}
				settingsDir := filepath.Join(home, folder)
				settingsPath := filepath.Join(settingsDir, filename)
				outsidePath := filepath.Join(outside, filename)
				body = []byte(strings.ReplaceAll(strings.ReplaceAll(string(body), "{home}", home), "{data_dir}", filepath.Join(home, ".defenseclaw")))
				if tc.connector == "codex" {
					body = materializePredecessorCodexTrust(t, body, settingsPath)
				}
				if err := os.WriteFile(outsidePath, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.linkKind == "parent" {
					if err := os.Symlink(outside, settingsDir); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.MkdirAll(settingsDir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outsidePath, settingsPath); err != nil {
						t.Fatal(err)
					}
				}
				if tc.connector == "codex" {
					previousRequirements := codexSystemRequirementsPathForInspection
					codexSystemRequirementsPathForInspection = func() (string, error) {
						return filepath.Join(root, "absent-requirements.toml"), nil
					}
					t.Cleanup(func() { codexSystemRequirementsPathForInspection = previousRequirements })
					t.Setenv("CODEX_HOME", settingsDir)
					pointCodexConfig(t, settingsPath)
				} else {
					t.Setenv("CLAUDE_CONFIG_DIR", settingsDir)
					previous := ClaudeCodeSettingsPathOverride
					ClaudeCodeSettingsPathOverride = settingsPath
					t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
				}
				opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookFailMode: "closed"}
				if err := CheckAgentSettings(conn, opts); err != nil {
					t.Fatalf("upgrade precheck refused user-owned settings at %s: %v", settingsPath, err)
				}
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatalf("upgrade setup through %s: %v", settingsPath, err)
				}
				if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
					t.Fatalf("hooks after upgrade: present=%v, err=%v", present, err)
				}
				if tc.linkKind == "parent" {
					if info, err := os.Lstat(settingsDir); err != nil || info.Mode()&os.ModeSymlink == 0 {
						t.Fatalf("setup replaced the dotfile directory link: %v", err)
					}
				} else {
					if info, err := os.Lstat(settingsPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
						t.Fatalf("setup replaced the settings file link: %v", err)
					}
					if target, err := os.Readlink(settingsPath); err != nil || target != outsidePath {
						t.Fatalf("settings file link target = %q, %v; want %s", target, err, outsidePath)
					}
					linked, err := os.ReadFile(settingsPath)
					if err != nil {
						t.Fatal(err)
					}
					outsideSettings, err := os.ReadFile(outsidePath)
					if err != nil {
						t.Fatal(err)
					}
					// OwnedHooksPresent checked the linked settings above; the
					// same hook-bearing bytes must be in the original target.
					if !bytes.Equal(linked, outsideSettings) {
						t.Fatal("setup did not write the hooks to the outside settings file")
					}
				}
				if tc.connector == "claudecode" {
					if _, err := conn.(*ClaudeCodeConnector).ConvertHooksForRollback(opts); err != nil {
						t.Fatalf("rollback conversion through linked .claude: %v", err)
					}
				}
			})
		}
	}
}

// The tagged registration golden uses {digest} for each Codex trust hash.
// Materialize the positional hashes that the predecessor wrote for this
// test's actual paths, leaving its hook matrix and other settings intact.
func materializePredecessorCodexTrust(t *testing.T, raw []byte, path string) []byte {
	t.Helper()
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	state := map[string]interface{}{}
	for eventType, rawGroups := range hooks {
		if eventType == "state" {
			continue
		}
		for groupIndex, rawGroup := range rawGroups.([]interface{}) {
			group := rawGroup.(map[string]interface{})
			for handlerIndex, rawHandler := range group["hooks"].([]interface{}) {
				handler := rawHandler.(map[string]interface{})
				eventKey := codexHookEventKeyLabel(eventType)
				hash, err := codexCommandHookHashForPlatform(runtime.GOOS, eventKey, group["matcher"], handler)
				if err != nil {
					t.Fatal(err)
				}
				key := codexHookStateKey(codexHookStateKeySource(path), eventKey, groupIndex, handlerIndex)
				state[key] = map[string]interface{}{"trusted_hash": hash}
			}
		}
	}
	hooks["state"] = state
	data, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A user may choose a dotfiles link, but a different account must not choose
// the settings that the per-user gateway will read or rewrite.
func TestOSSSetupRefusesForeignOwnedSettingsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership check")
	}
	for _, tc := range []struct {
		name, connector, linkKind string
	}{
		{"codex file", "codex", "file"},
		{"codex parent", "codex", "parent"},
		{"claude file", "claudecode", "file"},
		{"claude parent", "claudecode", "parent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			outside := t.TempDir()
			t.Setenv("HOME", home)
			folder, filename := ".codex", "config.toml"
			body := []byte("model = \"gpt-5\"\n")
			conn := Connector(NewCodexConnector())
			if tc.connector == "claudecode" {
				folder, filename, body = ".claude", "settings.json", []byte("{}\n")
				conn = NewClaudeCodeConnector()
			}
			dir := filepath.Join(home, folder)
			target := filepath.Join(outside, filename)
			if err := os.WriteFile(target, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.linkKind == "parent" {
				if err := os.Symlink(outside, dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, filename)); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, filename)
			if tc.connector == "codex" {
				pointCodexConfig(t, path)
			} else {
				previous := ClaudeCodeSettingsPathOverride
				ClaudeCodeSettingsPathOverride = path
				t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
			}
			previous := pluginGetUID
			pluginGetUID = func() int { return os.Getuid() + 1 }
			t.Cleanup(func() { pluginGetUID = previous })
			if err := CheckAgentSettings(conn, SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}); !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), "another account owns") {
				t.Fatalf("foreign-owned settings link precheck = %v", err)
			}
		})
	}
}

func TestClaudeCodeUserSettingsReadPathKeepsWindowsBehavior(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows keeps its original settings path for the native reader")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "dotfiles")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	parent := filepath.Join(home, ".claude")
	if err := os.Symlink(outside, parent); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	path := filepath.Join(parent, "settings.json")
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := claudeCodeUserSettingsReadPath(path); err != nil || got != path {
		t.Fatalf("Windows settings read path = %q, %v; want %q", got, err, path)
	}
}

func TestCheckAgentSettingsAllowsLinkedWindowsCodexHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows resolves the linked parent through its native path rules")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "dotfiles")
	for _, dir := range []string{home, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("USERPROFILE", home)
	if err := os.Symlink(outside, filepath.Join(home, ".codex")); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.WriteFile(filepath.Join(outside, "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pointCodexConfig(t, path)
	if err := CheckAgentSettings(NewCodexConnector(), SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}); err != nil {
		t.Fatalf("Windows Codex precheck refused readable settings through linked home: %v", err)
	}
}

// GAP-0615: a refusal of a Codex config.toml that does not parse names the
// file with the line and column of the error (file:line:col), not only the
// parser's message.
func TestCheckAgentSettingsNamesCodexSyntaxErrorLineAndColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := "model = \"gpt-5\"\n\n[otel]\nenvironment = \"dev\"\n[broken\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pointCodexConfig(t, path)
	err := CheckAgentSettings(NewCodexConnector(), SetupOpts{DataDir: t.TempDir()})
	if !errors.Is(err, ErrAgentConfigRefusal) {
		t.Fatalf("CheckAgentSettings = %v; want a refusal", err)
	}
	if !strings.Contains(err.Error(), path+":5:") || !strings.Contains(err.Error(), "line 5, column ") {
		t.Fatalf("refusal does not name %s:5:<col> (line 5 holds the broken table): %v", path, err)
	}
	var cfg map[string]interface{}
	parseErr := ParseCodexTOML(append([]byte{0xef, 0xbb, 0xbf}, body...), &cfg)
	var decode *toml.DecodeError
	if !errors.As(parseErr, &decode) || !strings.HasPrefix(parseErr.Error(), "line 5, column ") {
		t.Fatalf("ParseCodexTOML(BOM + broken table) = %v; want line 5 and an unwrappable parser error", parseErr)
	}
}
