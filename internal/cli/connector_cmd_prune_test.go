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
	testenv.SetHome(t, home)
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

// setUpAntigravityRollbackFromNewer sets Antigravity up over pristine on a
// newer install, moves that install aside as the saved data folder, and leaves
// an empty data folder: the older install, rolled back without ever having
// been initialized (no config.yaml, no connector state). It returns the
// vendor file, the saved folder and the data folder.
func setUpAntigravityRollbackFromNewer(t *testing.T, pristine []byte) (path, saved, dataDir string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	// Every per-OS config root (XDG, APPDATA, LOCALAPPDATA) moves with the
	// home, so a connector that resolves its folder from one of them cannot
	// reach the account that runs the tests.
	testenv.SetHome(t, root)
	dataDir = filepath.Join(root, ".defenseclaw")
	path = filepath.Join(root, ".gemini", "config", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := connector.AntigravityHooksPathOverride
	connector.AntigravityHooksPathOverride = path
	t.Cleanup(func() { connector.AntigravityHooksPathOverride = previous })
	if err := os.WriteFile(path, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	if err := connector.NewAntigravityConnector().Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if installed, err := os.ReadFile(path); err != nil || !bytes.Contains(installed, []byte("defenseclaw-antigravity-")) {
		t.Fatalf("setup file = %q, %v", installed, err)
	}
	saved = filepath.Join(root, "saved-newer-data")
	if err := os.Rename(dataDir, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return path, saved, dataDir
}

// A supported older install can be upgraded before it is initialized, so the
// rolled-back data folder has no config.yaml. The saved newer install's
// backup records still prove the exact vendor bytes: they are restored (GAP-0697).
func TestConnectorPruneOrphansRestoresBackupWhenRolledBackInstallHasNoConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pristine []byte
		state    []string
	}{
		{"operator content, no state", []byte("{\n  \"operator\": \"keep\"\n}\n"), nil},
		{"operator content, other connector active", []byte("{\n  \"operator\": \"keep\"\n}\n"), []string{"codex"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, tc.pristine)
			defer withConnectorState(t, dataDir, "codex")()
			if tc.state != nil {
				if err := connector.SaveActiveConnectors(dataDir, tc.state); err != nil {
					t.Fatal(err)
				}
			}
			cfg = nil
			_, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
			after, err := os.ReadFile(path)
			if err != nil || exitCode != 0 || !bytes.Equal(after, tc.pristine) {
				t.Fatalf("rollback exit=%d stderr=%q vendor file=%q, read=%v; want %q", exitCode, stderr, after, err, tc.pristine)
			}
		})
	}
}

// The operator edits the vendor file after the newer install set Antigravity
// up: the exact-hash restore keeps the edit, and the rollback still removes
// the registrations the older install does not name (GAP-0697). A connector the
// older install names keeps its registrations in the same edited file.
func TestConnectorPruneOrphansRollbackKeepsOperatorEditAndRemovesRegistrations(t *testing.T) {
	pristine := []byte("{\n  \"operator\": \"keep\"\n}\n")
	edit := func(t *testing.T, path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := bytes.Replace(data, []byte("\"operator\": \"keep\""), []byte("\"operator\": \"edited\""), 1)
		if bytes.Equal(edited, data) {
			t.Fatalf("operator field not found in %q", data)
		}
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		state []string
		want  bool // registrations stay
	}{
		{"no state", nil, false},
		{"other connector active", []string{"codex"}, false},
		{"antigravity still named", []string{"antigravity"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
			defer withConnectorState(t, dataDir, "codex")()
			if tc.state != nil {
				if err := connector.SaveActiveConnectors(dataDir, tc.state); err != nil {
					t.Fatal(err)
				}
			}
			edit(t, path)
			cfg = nil
			_, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
			after, err := os.ReadFile(path)
			if err != nil || exitCode != 0 {
				t.Fatalf("rollback exit=%d stderr=%q read=%v", exitCode, stderr, err)
			}
			if !bytes.Contains(after, []byte("\"edited\"")) {
				t.Fatalf("the operator edit was lost: %q", after)
			}
			if got := bytes.Contains(after, []byte("defenseclaw-antigravity-")); got != tc.want {
				t.Fatalf("registrations present=%v, want %v: %q", got, tc.want, after)
			}
		})
	}
}

// The benign twins: with no saved backup folder, or when the older install has
// a config.yaml that does not load, nothing is removed on a guess; and an
// Antigravity the older install still names keeps its registrations.
func TestConnectorPruneOrphansWithoutConfigStillGuessesNothing(t *testing.T) {
	pristine := []byte("{\n  \"operator\": \"keep\"\n}\n")
	registered := func(t *testing.T, path string) {
		t.Helper()
		if data, err := os.ReadFile(path); err != nil || !bytes.Contains(data, []byte("defenseclaw-antigravity-")) {
			t.Fatalf("registrations were touched: %q, %v", data, err)
		}
	}
	t.Run("no saved backup folder", func(t *testing.T) {
		path, _, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
		defer withConnectorState(t, dataDir, "codex")()
		cfg = nil
		_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir)
		if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
			t.Fatalf("stderr = %q", stderr)
		}
		registered(t, path)
	})
	t.Run("config.yaml present but not loaded", func(t *testing.T) {
		path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
		defer withConnectorState(t, dataDir, "codex")()
		if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("::: not yaml\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg = nil
		_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
		if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
			t.Fatalf("stderr = %q", stderr)
		}
		registered(t, path)
	})
	// A config.yaml link whose target is missing is a present config that does
	// not load, not an absent one: even with an operator edit in the vendor
	// file (kept by the exact-hash restore) no registration is removed.
	t.Run("config.yaml is a dangling link", func(t *testing.T) {
		path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
		defer withConnectorState(t, dataDir, "codex")()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := bytes.Replace(data, []byte("\"operator\": \"keep\""), []byte("\"operator\": \"edited\""), 1)
		if bytes.Equal(edited, data) {
			t.Fatalf("operator field not found in %q", data)
		}
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("temporarily-missing.yaml", filepath.Join(dataDir, "config.yaml")); err != nil {
			t.Skipf("config symlink not available: %v", err)
		}
		cfg = nil
		_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
		if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
			t.Fatalf("stderr = %q", stderr)
		}
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, edited) {
			t.Fatalf("a dangling config link caused cleanup: %q, %v", after, err)
		}
	})
	// The older data folder can be a link whose target is unavailable: that
	// proves nothing about the config or the active state inside it, so the
	// saved backups are not consumed and no registration is removed.
	t.Run("older data folder is a link that does not resolve", func(t *testing.T) {
		path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
		defer withConnectorState(t, dataDir, "codex")()
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := connector.SaveActiveConnectors(dataDir, []string{"antigravity"}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("old-config\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(dataDir), "old-data-target")
		if err := os.Rename(dataDir, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, dataDir); err != nil {
			t.Skipf("data folder symlink not available: %v", err)
		}
		if err := os.Rename(target, target+"-offline"); err != nil {
			t.Fatal(err)
		}
		cfg = nil
		_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
		if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
			t.Fatalf("stderr = %q", stderr)
		}
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
			t.Fatalf("an unavailable data folder caused cleanup: %q, %v", after, err)
		}
	})
	// A saved folder that is missing, or holds no connector backup records, is
	// not rollback evidence.
	for _, tc := range []struct {
		name  string
		saved func(t *testing.T, saved, dataDir string) string
	}{
		{"saved backup folder is missing", func(_ *testing.T, _, dataDir string) string {
			return filepath.Join(filepath.Dir(dataDir), "missing-saved-newer-data")
		}},
		{"saved backup folder holds no backup records", func(t *testing.T, _, dataDir string) string {
			empty := filepath.Join(filepath.Dir(dataDir), "empty-saved-data")
			if err := os.MkdirAll(empty, 0o700); err != nil {
				t.Fatal(err)
			}
			return empty
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
			defer withConnectorState(t, dataDir, "codex")()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg = nil
			_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", tc.saved(t, saved, dataDir))
			if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") {
				t.Fatalf("stderr = %q", stderr)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("an unconfirmed saved folder caused cleanup: %q, %v", after, err)
			}
		})
	}
	t.Run("connector still named by the older install", func(t *testing.T) {
		path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
		defer withConnectorState(t, dataDir, "codex")()
		if err := connector.SaveActiveConnectors(dataDir, []string{"antigravity"}); err != nil {
			t.Fatal(err)
		}
		cfg = nil
		_, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
		if exitCode != 0 {
			t.Fatalf("exit=%d stderr=%q", exitCode, stderr)
		}
		registered(t, path)
	})
}

// Rollback evidence for a missing config.yaml is the connector backup records
// of the saved newer install, not a folder of that name: an empty folder, one
// with only unrelated files, or one with a record that is rejected (it does not
// parse, or does not match its saved digest) removes nothing (GAP-0697).
func TestConnectorPruneOrphansWithoutConfigNeedsVerifiedBackupRecords(t *testing.T) {
	pristine := []byte("{\n  \"operator\": \"keep\"\n}\n")
	eachRecord := func(t *testing.T, saved string, fn func(path string)) {
		t.Helper()
		found := false
		err := filepath.Walk(filepath.Join(saved, "connector_backups"), func(p string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !info.IsDir() && strings.HasSuffix(p, ".json") {
				found = true
				fn(p)
			}
			return nil
		})
		if err != nil || !found {
			t.Fatalf("no backup record to change: found=%v err=%v", found, err)
		}
	}
	resetRoot := func(t *testing.T, saved string) string {
		t.Helper()
		root := filepath.Join(saved, "connector_backups")
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		return root
	}
	setTarget := func(target func(dataDir string) string) func(t *testing.T, saved string) {
		return func(t *testing.T, saved string) {
			t.Helper()
			eachRecord(t, saved, func(p string) {
				var rec map[string]any
				data, err := os.ReadFile(p)
				if err != nil || json.Unmarshal(data, &rec) != nil {
					t.Fatalf("read record: %v", err)
				}
				rec["path"] = target(filepath.Dir(filepath.Dir(filepath.Dir(p))))
				data, err = json.Marshal(rec)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, saved string)
	}{
		{"empty connector_backups folder", func(t *testing.T, saved string) {
			resetRoot(t, saved)
		}},
		{"connector_backups holds only unrelated text", func(t *testing.T, saved string) {
			root := resetRoot(t, saved)
			if err := os.WriteFile(filepath.Join(root, "readme.txt"), []byte("no backup records"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a connector folder holds no record", func(t *testing.T, saved string) {
			eachRecord(t, saved, func(p string) {
				if err := os.Rename(p, strings.TrimSuffix(p, ".json")+".txt"); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"a record does not parse", func(t *testing.T, saved string) {
			eachRecord(t, saved, func(p string) {
				if err := os.WriteFile(p, []byte("{invalid backup record"), 0o600); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"a record does not match its saved digest", func(t *testing.T, saved string) {
			eachRecord(t, saved, func(p string) {
				var rec map[string]any
				data, err := os.ReadFile(p)
				if err != nil || json.Unmarshal(data, &rec) != nil {
					t.Fatalf("read record: %v", err)
				}
				rec["pristine_sha256"] = strings.Repeat("0", 64)
				data, err = json.Marshal(rec)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"a record names no target path", setTarget(func(string) string { return "" })},
		{"a record names a relative target path", setTarget(func(string) string { return "relative-hooks.json" })},
		{"a record names a target outside the account home", setTarget(func(string) string {
			return filepath.Join(t.TempDir(), "elsewhere", "hooks.json")
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
			defer withConnectorState(t, dataDir, "codex")()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(before, []byte("defenseclaw-antigravity-")) {
				t.Fatalf("setup made no owned registration: %q", before)
			}
			tc.change(t, saved)
			cfg = nil
			_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stderr, "config.yaml is not loaded; nothing was removed") || !bytes.Equal(after, before) {
				t.Fatalf("unproven saved folder allowed cleanup: stderr=%q after-matches-before=%v", stderr, bytes.Equal(after, before))
			}
		})
	}
}

// The rollback fixture's home covers every config root a connector reads. A
// runner that sets XDG_CONFIG_HOME or APPDATA (Windows) outside the fixture
// must not leak into the Devin config path the prune tests write through.
func TestRollbackFixtureHomeCoversConnectorConfigRoots(t *testing.T) {
	foreign := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", foreign)
	t.Setenv("APPDATA", foreign)
	t.Setenv("LOCALAPPDATA", foreign)
	_, _, dataDir := setUpAntigravityRollbackFromNewer(t, []byte("{}\n"))
	devinPath := connector.DevinHooksConfigPath(connector.SetupOpts{DataDir: dataDir})
	home := filepath.Dir(dataDir)
	if rel, err := filepath.Rel(home, devinPath); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("Devin config path %q is outside the fixture home %q", devinPath, home)
	}
}

// A connector whose config root the operator moved outside the account home
// (Devin with an absolute XDG_CONFIG_HOME) leaves a valid backup record that
// the restore skips. It must not stop the rollback from restoring and
// cleaning the connectors whose files are under the home.
func TestConnectorPruneOrphansRollbackIgnoresBackupOutsideAccountHome(t *testing.T) {
	pristine := []byte("{\"operator\":\"before\"}\n")
	path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
	defer withConnectorState(t, dataDir, "codex")()
	externalConfigRoot := t.TempDir()
	// Devin reads XDG_CONFIG_HOME on macOS and Linux and %APPDATA% on Windows.
	t.Setenv("XDG_CONFIG_HOME", externalConfigRoot)
	t.Setenv("APPDATA", externalConfigRoot)
	// Run Devin Setup against the newer data folder, then swap the folders the
	// way the real rollback does.
	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, dataDir); err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	// Check where Setup will write before it writes: a path outside the
	// temporary root would be the runner account's own Devin config.
	devinPath := connector.DevinHooksConfigPath(opts)
	if devinPath != filepath.Join(externalConfigRoot, "devin", "config.json") {
		t.Fatalf("Devin config path = %q, want the custom config root", devinPath)
	}
	if err := connector.NewDevinConnector().Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dataDir, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(saved, "connector_backups", "devin", "config.json")); err != nil {
		t.Fatalf("Devin setup made no backup record: %v", err)
	}
	cfg = nil
	_, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--data-dir", dataDir, "--rollback-backups-dir", saved)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 0 || !bytes.Equal(after, pristine) {
		t.Fatalf("a backup outside the account home blocked the restore: exit=%d stderr=%q antigravity=%q", exitCode, stderr, after)
	}
	// The restore skips the file outside the home; the owned-entry cleanup
	// still takes DefenseClaw out of it.
	if devinAfter, err := os.ReadFile(devinPath); err != nil || strings.Contains(strings.ToLower(string(devinAfter)), "defenseclaw") {
		t.Fatalf("the file outside the account home still holds DefenseClaw entries: %v", err)
	}
}

// A backup record whose target sits inside the older data folder is no
// rollback proof however --data-dir is spelled: absolute, relative to the
// working directory, or through a link (GAP-0697). The same unmodified record
// with a linked data folder still rolls back.
func TestConnectorPruneOrphansDataDirSpellingDoesNotValidateInDataBackupTarget(t *testing.T) {
	pristine := []byte("{\"operator\":\"before\"}\n")
	for _, tc := range []struct {
		name     string
		inData   bool
		spelling string
	}{
		{"absolute", true, "absolute"},
		{"relative", true, "relative"},
		{"linked", true, "linked"},
		{"linked, record names the agent file", false, "linked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, saved, dataDir := setUpAntigravityRollbackFromNewer(t, pristine)
			defer withConnectorState(t, dataDir, "codex")()
			installed, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.inData {
				found := false
				walkErr := filepath.Walk(filepath.Join(saved, "connector_backups"), func(p string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() || !strings.HasSuffix(p, ".json") {
						return err
					}
					var rec map[string]any
					data, err := os.ReadFile(p)
					if err != nil || json.Unmarshal(data, &rec) != nil {
						t.Fatalf("read record: %v", err)
					}
					rec["path"] = filepath.Join(dataDir, "config.json")
					if data, err = json.Marshal(rec); err != nil {
						return err
					}
					found = true
					return os.WriteFile(p, data, 0o600)
				})
				if walkErr != nil || !found {
					t.Fatalf("no backup record to change: found=%v err=%v", found, walkErr)
				}
			}
			flagDir := dataDir
			switch tc.spelling {
			case "relative":
				t.Chdir(filepath.Dir(dataDir))
				flagDir = filepath.Base(dataDir)
			case "linked":
				flagDir = filepath.Join(filepath.Dir(dataDir), "linked-older-data")
				if err := os.Symlink(dataDir, flagDir); err != nil {
					t.Skipf("cannot create a link: %v", err)
				}
			}
			cfg = nil
			_, stderr, _ := runConnectorCmd(t, "prune-orphans", "--data-dir", flagDir, "--rollback-backups-dir", saved)
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			refused := strings.Contains(stderr, "nothing was removed") && bytes.Equal(after, installed)
			if tc.inData && !refused {
				t.Fatalf("in-data target accepted with a %s data folder: stderr=%q", tc.spelling, stderr)
			}
			if !tc.inData && !bytes.Equal(after, pristine) {
				t.Fatalf("rollback with a %s data folder did not restore: stderr=%q file=%q", tc.spelling, stderr, after)
			}
		})
	}
}
