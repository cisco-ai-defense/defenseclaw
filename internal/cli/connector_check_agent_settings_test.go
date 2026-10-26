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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/spf13/cobra"
)

// GAP-0615: `defenseclaw setup codex` with a config.toml that does not parse
// restarted the gateway, which then could not start Codex, and the rollback
// left the gateway stopped. Setup now asks this command first; it names the
// file and changes nothing.
func TestConnectorCheckAgentSettingsRefusesCodexConfigThatDoesNotParse(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	path := filepath.Join(t.TempDir(), "config.toml")
	broken := "model = \"gpt-5\"\n[t6z2_broken\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = path
	t.Cleanup(func() { connector.CodexConfigPathOverride = previous })

	stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not JSON: %q (%v)", stdout, err)
	}
	reason, _ := payload["reason"].(string)
	if payload["refused"] != true || !strings.Contains(reason, path) || !strings.Contains(reason, "does not parse") {
		t.Fatalf("payload = %v; want a refusal naming %s", payload, path)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != broken {
		t.Fatalf("the check changed config.toml: %q (%v)", after, err)
	}
	if entries, _ := os.ReadDir(dataDir); len(entries) != 0 {
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".lock") {
				t.Errorf("the check wrote %s into the data dir", entry.Name())
			}
		}
	}

	if err := os.WriteFile(path, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	connectorFlagJSON = false
	if _, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex"); code != 0 {
		t.Fatalf("usable config: exit = %d, stderr=%q", code, stderr)
	}
	if _, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "no-such-agent"); code != 2 {
		t.Fatalf("unknown connector: exit = %d, want 2 (stderr=%q)", code, stderr)
	}
}

func TestConnectorCheckAgentSettingsUsesRequestedWorkspace(t *testing.T) {
	if flag := connectorCheckAgentSettingsCmd.Flags().Lookup("workspace-dir"); flag == nil || !flag.Hidden {
		t.Fatal("check-agent-settings must accept Setup's hidden requested workspace")
	}
	for _, name := range []string{"claudecode", "copilot"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			oldWorkspace := filepath.Join(root, "old-workspace")
			newWorkspace := filepath.Join(root, "new-workspace")
			for _, path := range []string{home, oldWorkspace, newWorkspace} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			dataDir := testenv.PrivateTempDir(t)
			defer withConnectorState(t, dataDir, name)()
			cfg.Claw.WorkspaceDir = oldWorkspace
			settingsDir := filepath.Join(oldWorkspace, ".claude")
			if name == "copilot" {
				settingsDir = filepath.Join(oldWorkspace, ".github", "copilot")
				t.Setenv("COPILOT_HOME", filepath.Join(home, ".copilot"))
			} else {
				userSettings := filepath.Join(home, ".claude", "settings.json")
				if err := os.MkdirAll(filepath.Dir(userSettings), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(userSettings, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				previous := connector.ClaudeCodeSettingsPathOverride
				connector.ClaudeCodeSettingsPathOverride = userSettings
				t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
			}
			if err := os.MkdirAll(settingsDir, 0o700); err != nil {
				t.Fatal(err)
			}
			refusingSettings := filepath.Join(settingsDir, "settings.json")
			if err := os.WriteFile(refusingSettings, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			check := func(requested *string) (bool, string) {
				t.Helper()
				var out bytes.Buffer
				cmd := &cobra.Command{Use: "check-agent-settings"}
				cmd.Flags().String("workspace-dir", "", "")
				if requested != nil {
					if err := cmd.Flags().Set("workspace-dir", *requested); err != nil {
						t.Fatal(err)
					}
				}
				cmd.SetOut(&out)
				connectorFlagJSON = true
				var code int
				connectorExit = func(exit int) { code = exit }
				if err := runConnectorCheckAgentSettings(cmd, nil); err != nil {
					t.Fatal(err)
				}
				var result struct {
					Refused bool   `json:"refused"`
					Reason  string `json:"reason"`
				}
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatalf("check response %q: %v", out.String(), err)
				}
				if result.Refused != (code == 1) {
					t.Fatalf("check exit %d disagrees with response %q", code, out.String())
				}
				return result.Refused, result.Reason
			}
			if refused, reason := check(nil); !refused || !strings.Contains(reason, refusingSettings) {
				t.Fatalf("old workspace was not refused: %q", reason)
			}
			for _, requested := range []string{newWorkspace, ""} {
				if refused, reason := check(&requested); refused {
					t.Fatalf("requested workspace %q still checked the old workspace: %s", requested, reason)
				}
			}
			newSettings := filepath.Join(newWorkspace, ".claude", "settings.json")
			if name == "copilot" {
				newSettings = filepath.Join(newWorkspace, ".github", "copilot", "settings.json")
			}
			if err := os.MkdirAll(filepath.Dir(newSettings), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(newSettings, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if refused, reason := check(&newWorkspace); !refused || !strings.Contains(reason, newSettings) {
				t.Fatalf("requested workspace policy was not enforced: %q", reason)
			}
		})
	}
}

func TestConnectorCheckAgentSettingsFollowsExplicitCodexMigrationRoot(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	oldRoot := filepath.Join(home, "old-codex")
	newRoot := filepath.Join(home, "new-codex")
	for _, path := range []string{oldRoot, newRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", oldRoot)
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", "")
	dataDir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "codex")()
	if err := connector.NewCodexConnector().Setup(context.Background(), connector.SetupOpts{
		DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookFailMode: "closed",
	}); err != nil {
		t.Fatalf("register old Codex root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oldRoot, "config.toml"), []byte("[features]\nhooks = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newRoot, "config.toml"), []byte("[features]\nhooks = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", newRoot)
	if stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json"); code != 1 || !strings.Contains(stdout, filepath.Join(oldRoot, "config.toml")) {
		t.Fatalf("without migration marker, expected old-root refusal: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", newRoot)
	if stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json"); code != 0 || !strings.Contains(stdout, `"refused":false`) {
		t.Fatalf("explicit new-root precheck: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// GAP-1325: `defenseclaw setup claude-code` saved its change and reported
// success while the data directory's shared hook config was malformed
// (fail_modes null), which every hook of the data directory closes on. The
// check setup runs first refuses it for any connector and changes nothing.
func TestConnectorCheckAgentSettingsRefusesMalformedSharedHookSidecar(t *testing.T) {
	for _, name := range []string{"claudecode", "cursor"} {
		t.Run(name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			defer withConnectorState(t, dataDir, name)()
			settings := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(settings, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := connector.ClaudeCodeSettingsPathOverride
			connector.ClaudeCodeSettingsPathOverride = settings
			t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
			sidecar := filepath.Join(dataDir, "hooks", ".hookcfg")
			malformed := `{"version":2,"fail_modes":null,"legacy_fail_mode":"open"}`
			if err := os.MkdirAll(filepath.Dir(sidecar), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sidecar, []byte(malformed), 0o600); err != nil {
				t.Fatal(err)
			}
			connectorFlagJSON = true
			stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", name, "--json")
			if code != 1 {
				t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
				t.Fatalf("stdout is not JSON: %q (%v)", stdout, err)
			}
			reason, _ := payload["reason"].(string)
			if payload["refused"] != true || !strings.Contains(reason, sidecar) || !strings.Contains(reason, "malformed") {
				t.Fatalf("payload = %v; want a refusal naming %s", payload, sidecar)
			}
			if after, err := os.ReadFile(sidecar); err != nil || string(after) != malformed {
				t.Fatalf("the check changed the sidecar: %q (%v)", after, err)
			}
		})
	}
}
