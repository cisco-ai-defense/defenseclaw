// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const operatorClaudeSettings = `{"env":{"OPERATOR_FLAG":"1"},"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"/opt/operator/prompt-check.sh"}]}]}}`

// setUpClaudeCodeAfterOperator writes the operator's own Claude Code settings,
// then runs the claudecode Setup over them, as `defenseclaw setup claudecode`
// does, and returns the settings path.
func setUpClaudeCodeAfterOperator(t *testing.T, dataDir string) string {
	t.Helper()
	settingsPath := filepath.Join(testenv.PrivateTempDir(t), "settings.json")
	if err := os.WriteFile(settingsPath, []byte(operatorClaudeSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	if err := connector.NewClaudeCodeConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("claudecode setup: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), filepath.Join(dataDir, "hooks")) {
		t.Fatalf("setup wrote no DefenseClaw hook entries:\n%s", data)
	}
	return settingsPath
}

// rel-1-0-1:GAP-0009: a rollback restored the data directory from before
// claudecode was set up, so ~/.claude/settings.json kept DefenseClaw hook
// entries that run a hook script the restored install never had, and Claude
// Code blocked every prompt. prune-orphans removes those entries, and only
// those: the operator's hook and env stay.
func TestConnectorPruneOrphansRemovesHooksOfAConnectorRolledBackAway(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX hook layout")
	}
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	settingsPath := setUpClaudeCodeAfterOperator(t, dataDir)
	// The rollback: the data directory of the install before the setup.
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans")
	if exitCode != 0 || strings.TrimSpace(stderr) != "" || !strings.Contains(stdout, "claudecode is not configured: removed") {
		t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), dataDir) || strings.Contains(strings.ToLower(string(after)), "defenseclaw") {
		t.Fatalf("DefenseClaw entries left in settings.json:\n%s", after)
	}
	var settings struct {
		Env   map[string]any `json:"env"`
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(after, &settings); err != nil {
		t.Fatalf("settings.json after prune: %v\n%s", err, after)
	}
	prompt := settings.Hooks["UserPromptSubmit"]
	if settings.Env["OPERATOR_FLAG"] != "1" || len(prompt) != 1 || len(prompt[0].Hooks) != 1 ||
		prompt[0].Hooks[0].Command != "/opt/operator/prompt-check.sh" {
		t.Fatalf("the operator's own settings changed:\n%s", after)
	}

	// Nothing is left to remove, so a second run says nothing.
	stdout, stderr, exitCode = runConnectorCmd(t, "prune-orphans")
	if exitCode != 0 || strings.TrimSpace(stdout+stderr) != "" {
		t.Fatalf("second prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestConnectorPruneOrphansRestoresAntigravityAfterRollback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial []byte
		edited  bool
	}{
		{"empty file", []byte("{}\n"), false},
		{"operator content", []byte("{\n  \"operator\": \"keep\"\n}\n"), false},
		{"absent file", nil, false},
		{"operator edit after setup", []byte("{}\n"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			t.Setenv("HOME", root)
			t.Setenv("USERPROFILE", root)
			dataDir := filepath.Join(root, ".defenseclaw")
			defer withConnectorState(t, dataDir, "codex")()
			path := filepath.Join(root, ".gemini", "config", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			previous := connector.AntigravityHooksPathOverride
			connector.AntigravityHooksPathOverride = path
			t.Cleanup(func() { connector.AntigravityHooksPathOverride = previous })
			if tc.initial != nil {
				if err := os.WriteFile(path, tc.initial, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			conn := connector.NewAntigravityConnector()
			if err := conn.Setup(context.Background(), connector.SetupOpts{
				DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token",
			}); err != nil {
				t.Fatalf("antigravity setup: %v", err)
			}
			installed, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(installed, []byte("defenseclaw-antigravity-stop")) {
				t.Fatalf("antigravity registration = %q, %v", installed, err)
			}
			if tc.edited {
				var doc map[string]any
				if err := json.Unmarshal(installed, &doc); err != nil {
					t.Fatal(err)
				}
				doc["operator"] = "later"
				edited, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, edited, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// Rollback swaps the data folder; the vendor file stays outside it.
			saved := filepath.Join(root, "saved")
			if err := os.Rename(dataDir, saved); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dataDir, "previous"), 0o700); err != nil {
				t.Fatal(err)
			}
			saved = filepath.Join(dataDir, "previous", "data")
			if err := os.Rename(filepath.Join(root, "saved"), saved); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--connector", "antigravity", "--rollback-backups-dir", saved)
			wantAction := "restored the previous vendor file"
			if tc.edited {
				wantAction = "antigravity is not configured: removed"
			}
			if exitCode != 0 || strings.TrimSpace(stderr) != "" || !strings.Contains(stdout, wantAction) {
				t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			after, err := os.ReadFile(path)
			if tc.edited {
				var doc map[string]any
				if err != nil || json.Unmarshal(after, &doc) != nil || len(doc) != 1 || doc["operator"] != "later" {
					t.Fatalf("edited hooks.json after rollback = %q, %v", after, err)
				}
			} else if tc.initial == nil {
				if !os.IsNotExist(err) {
					t.Fatalf("hooks.json after rollback = %q, %v; want absent", after, err)
				}
			} else if err != nil || !bytes.Equal(after, tc.initial) {
				t.Fatalf("hooks.json after rollback = %q, %v; want %q", after, err, tc.initial)
			}
		})
	}
}

// A connector that config.yaml or the runtime connector state names is never
// an orphan, even while its hook script is missing (doctor reports that).
func TestConnectorPruneOrphansKeepsConfiguredConnectors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX hook layout")
	}
	for _, source := range []string{"config", "runtime state"} {
		t.Run(source, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			primary := "codex"
			if source == "config" {
				primary = "claudecode"
			}
			defer withConnectorState(t, dataDir, primary)()
			settingsPath := setUpClaudeCodeAfterOperator(t, dataDir)
			if source == "runtime state" {
				if err := connector.SaveActiveConnectors(dataDir, []string{"claudecode"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(dataDir, "hooks", "claude-code-hook.sh")); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}

			stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--connector", "claudecode")
			if exitCode != 0 || strings.TrimSpace(stdout+stderr) != "" {
				t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			after, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("a configured connector's settings changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// Without config.yaml nothing tells what is configured: nothing is removed.
func TestConnectorPruneOrphansNeedsTheConfig(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	cfg = nil
	_, stderr, _ := runConnectorCmd(t, "prune-orphans")
	if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
		t.Fatalf("stderr = %q", stderr)
	}
}

const operatorOpenCodePlugin = "export const Operator = async () => ({});\n"

// setUpOpenCodeNextToOperatorPlugin runs the opencode Setup, as `defenseclaw
// setup opencode` does, into a plugin folder that already holds the
// operator's own plugin, and returns that folder.
func setUpOpenCodeNextToOperatorPlugin(t *testing.T, dataDir string) string {
	t.Helper()
	home := testenv.PrivateTempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	configDir := filepath.Join(home, ".config", "opencode")
	t.Setenv("OPENCODE_CONFIG_DIR", configDir)
	pluginDir := filepath.Join(configDir, "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "operator.js"), []byte(operatorOpenCodePlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	// The gateway mints the plugin's credential for a configured connector.
	token, err := connector.EnsureHookAPIToken(dataDir, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: token, HookFailMode: "closed"}
	if err := connector.NewOpenCodeConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("opencode setup: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(pluginDir, "defenseclaw.js"))
	if err != nil || !strings.HasPrefix(string(data), "// defenseclaw-managed-plugin v") {
		t.Fatalf("setup wrote no DefenseClaw plugin: %v", err)
	}
	return pluginDir
}

func assertOperatorOpenCodePluginKept(t *testing.T, pluginDir string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pluginDir, "operator.js"))
	if err != nil || string(data) != operatorOpenCodePlugin {
		t.Fatalf("the operator's own OpenCode plugin changed: %q, %v", data, err)
	}
}

// rel-1-0-2:GAP-0001 (rel-1-0-1:GAP-0009) for a plugin-file connector:
// OpenCode is registered by its plugin file, not by hook entries, and the
// plugin reads its credential from <data>/hooks. A rollback to the data
// directory from before `setup opencode` has no such credential, and the
// gateway mints none for a connector it does not configure, so the plugin
// refused every OpenCode tool call. prune-orphans removes that plugin, and
// only it: the operator's plugin in the same folder stays.
func TestConnectorPruneOrphansRemovesTheOpenCodePluginOfARolledBackSetup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX plugin folder layout")
	}
	dataDir := testenv.PrivateTempDir(t)
	pluginDir := setUpOpenCodeNextToOperatorPlugin(t, dataDir)
	defer withConnectorState(t, dataDir, "claudecode")()
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans")
	if exitCode != 0 || strings.TrimSpace(stderr) != "" || !strings.Contains(stdout, "opencode is not configured: removed") {
		t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Join(pluginDir, "defenseclaw.js")); !os.IsNotExist(err) {
		t.Fatalf("the DefenseClaw OpenCode plugin is still there: %v", err)
	}
	assertOperatorOpenCodePluginKept(t, pluginDir)

	stdout, stderr, exitCode = runConnectorCmd(t, "prune-orphans", "--connector", "opencode")
	if exitCode != 0 || strings.TrimSpace(stdout+stderr) != "" {
		t.Fatalf("second prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

// A configured OpenCode keeps its plugin, even with its credential missing
// (doctor and the gateway handle that), and so does the plugin of another
// data directory.
func TestConnectorPruneOrphansKeepsAConfiguredOrForeignOpenCodePlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX plugin folder layout")
	}
	dataDir := testenv.PrivateTempDir(t)
	pluginDir := setUpOpenCodeNextToOperatorPlugin(t, dataDir)
	before, err := os.ReadFile(filepath.Join(pluginDir, "defenseclaw.js"))
	if err != nil {
		t.Fatal(err)
	}
	tokenFile, err := connector.HookAPITokenFilePath(dataDir, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"configured": dataDir, "another data directory": testenv.PrivateTempDir(t)} {
		t.Run(name, func(t *testing.T) {
			primary := "claudecode"
			if dir == dataDir {
				primary = "opencode"
			}
			defer withConnectorState(t, dir, primary)()
			stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--connector", "opencode")
			if exitCode != 0 || strings.TrimSpace(stdout+stderr) != "" {
				t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			after, err := os.ReadFile(filepath.Join(pluginDir, "defenseclaw.js"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("the OpenCode plugin changed: %v", err)
			}
			assertOperatorOpenCodePluginKept(t, pluginDir)
		})
	}
}
