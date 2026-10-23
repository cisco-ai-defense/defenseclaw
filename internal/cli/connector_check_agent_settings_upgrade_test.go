// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

// The tagged 1.0.2 and 1.0.3 Claude Code settings snapshots have the same
// bytes. A switch must inspect the workspace Setup requested, not the old
// workspace still recorded in config.yaml before the transaction commits.
func TestClaudeCodeWorkspaceUpgradeChecksRequestedScope(t *testing.T) {
	for _, predecessor := range []string{"1.0.2", "1.0.3"} {
		t.Run(predecessor, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			oldWorkspace := filepath.Join(root, "old-workspace")
			newWorkspace := filepath.Join(root, "new-workspace")
			for _, dir := range []string{filepath.Join(home, ".claude"), filepath.Join(oldWorkspace, ".claude"), newWorkspace} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
			dataDir := testenv.PrivateTempDir(t)
			defer withConnectorState(t, dataDir, "claudecode")()
			cfg.Claw.WorkspaceDir = oldWorkspace
			predecessorSettings, err := os.ReadFile(filepath.Join("..", "gateway", "connector", "testdata", "predecessor_1_0_2_1_0_3", "claudecode.json"))
			if err != nil {
				t.Fatal(err)
			}
			predecessorSettings = []byte(strings.ReplaceAll(strings.ReplaceAll(string(predecessorSettings), "{home}", home), "{data_dir}", dataDir))
			userPath := filepath.Join(home, ".claude", "settings.json")
			if err := os.WriteFile(userPath, predecessorSettings, 0o600); err != nil {
				t.Fatal(err)
			}
			oldPolicy := filepath.Join(oldWorkspace, ".claude", "settings.json")
			if err := os.WriteFile(oldPolicy, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
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
					t.Fatalf("check exit %d disagrees with %q", code, out.String())
				}
				return result.Refused, result.Reason
			}
			if refused, reason := check(nil); !refused || !strings.Contains(reason, oldPolicy) {
				t.Fatalf("old workspace should refuse: %q", reason)
			}
			if refused, reason := check(&newWorkspace); refused {
				t.Fatalf("upgrade switch to new workspace checked the old policy: %q", reason)
			}
			empty := ""
			if refused, reason := check(&empty); refused {
				t.Fatalf("upgrade switch to global scope checked the old policy: %q", reason)
			}
			if cfg.Claw.WorkspaceDir != oldWorkspace {
				t.Fatalf("precheck changed saved workspace to %q", cfg.Claw.WorkspaceDir)
			}
			if after, err := os.ReadFile(userPath); err != nil || !bytes.Equal(after, predecessorSettings) {
				t.Fatalf("precheck changed predecessor settings: %v", err)
			}
			conn := connector.NewClaudeCodeConnector()
			opts := connector.SetupOpts{
				DataDir: dataDir, WorkspaceDir: newWorkspace, APIAddr: "127.0.0.1:18970",
				APIToken: "test-token", HookFailMode: "closed",
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("upgrade setup in requested workspace: %v", err)
			}
			if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
				t.Fatalf("hooks after workspace switch: present=%t, err=%v", present, err)
			}
			if after, err := os.ReadFile(oldPolicy); err != nil || string(after) != `{"disableAllHooks":true}` {
				t.Fatalf("upgrade changed the old workspace policy: %q, %v", after, err)
			}
		})
	}
}

// A 1.0.2 or 1.0.3 Codex registration pins the previous root until an
// explicit migration. Test both directions so a precheck cannot accidentally
// accept a bad new root or refuse a good one using the predecessor's file.
func TestCodexRootUpgradePrecheckInspectsSelectedRoot(t *testing.T) {
	for _, predecessor := range []string{"1.0.2", "1.0.3"} {
		t.Run(predecessor, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			oldRoot := filepath.Join(home, "old-codex")
			newRoot := filepath.Join(home, "new-codex")
			for _, dir := range []string{oldRoot, newRoot} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("CODEX_HOME", oldRoot)
			t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", "")
			dataDir := testenv.PrivateTempDir(t)
			defer withConnectorState(t, dataDir, "codex")()
			conn := connector.NewCodexConnector()
			if err := conn.Setup(context.Background(), connector.SetupOpts{
				DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookFailMode: "closed",
			}); err != nil {
				t.Fatalf("register previous Codex root: %v", err)
			}
			oldPath := filepath.Join(oldRoot, "config.toml")
			newPath := filepath.Join(newRoot, "config.toml")
			predecessorSettings, err := os.ReadFile(filepath.Join("..", "gateway", "connector", "testdata", "predecessor_1_0_2_1_0_3", "codex.toml"))
			if err != nil {
				t.Fatal(err)
			}
			predecessorSettings = []byte(strings.ReplaceAll(strings.ReplaceAll(string(predecessorSettings), "{home}", home), "{data_dir}", dataDir))
			if err := os.WriteFile(oldPath, predecessorSettings, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CODEX_HOME", newRoot)
			if err := os.WriteFile(newPath, []byte("[features]\nhooks = false\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json"); code != 0 {
				t.Fatalf("ordinary check should still see previous root: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", newRoot)
			if stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json"); code != 1 || !strings.Contains(stdout, newPath) {
				t.Fatalf("bad selected root was accepted: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if err := os.WriteFile(oldPath, append(append([]byte(nil), predecessorSettings...), []byte("\n[features]\nhooks = false\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(newPath, []byte("[features]\nhooks = true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", "")
			if stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json"); code != 1 || !strings.Contains(stdout, oldPath) {
				t.Fatalf("ordinary check ignored previous-root refusal: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			t.Setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", newRoot)
			if stdout, stderr, code := runConnectorCmd(t, "check-agent-settings", "--connector", "codex", "--json"); code != 0 || !strings.Contains(stdout, `"refused":false`) {
				t.Fatalf("good selected root was refused: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}
