// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// kiroHookCommandsUnder returns every hook command in the Kiro JSON files
// under root, with the file it is in.
func kiroHookCommandsUnder(t *testing.T, root string) map[string]string {
	t.Helper()
	commands := map[string]string{}
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				if command, ok := item.(string); ok && key == "command" && strings.TrimSpace(command) != "" {
					commands[command] = path
					continue
				}
				walk(path, item)
			}
		case []any:
			for _, item := range v {
				walk(path, item)
			}
		}
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !entry.Type().IsRegular() || filepath.Ext(path) != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var decoded any
		if json.Unmarshal(data, &decoded) == nil {
			walk(path, decoded)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return commands
}

// rel-1-0-10 GAP-1221: 1.0.10 set Kiro up, then `defenseclaw rollback` went
// back to an install that does not guard Kiro. prepare-rollback converted the
// Kiro hooks the user had edited since into the form the target owns, the
// installer swapped the data folders, and its prune with this release's
// gateway (--rollback-backups-dir, the saved newer data) left them on Windows:
// the restored folder holds no proof that its install set Kiro up. The older
// install then neither removed nor guarded them ("Connector kiro is already
// absent"), and Kiro failed closed without its token. The prune now removes
// every DefenseClaw Kiro hook the rollback left, on every OS.
func TestConnectorPruneOrphansRemovesTheKiroHooksARollbackLeft(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	kiroHome := filepath.Join(root, ".kiro")
	previousHome := connector.KiroHomeOverride
	connector.KiroHomeOverride = kiroHome
	t.Cleanup(func() { connector.KiroHomeOverride = previousHome })
	dataDir := filepath.Join(root, ".defenseclaw")
	saved := filepath.Join(root, "previous", "data")
	for _, dir := range []string{dataDir, filepath.Dir(saved)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	kiro := connector.NewKiroConnector()
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookFailMode: "closed"}
	if err := kiro.Setup(context.Background(), opts); err != nil {
		t.Fatalf("kiro setup: %v", err)
	}
	// The user edits the DefenseClaw agent after setup, so the rollback
	// converts its entries rather than putting the file back as it was.
	agentPath := filepath.Join(kiroHome, "agents", "defenseclaw.json")
	data, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	var agent map[string]any
	if err := json.Unmarshal(data, &agent); err != nil {
		t.Fatal(err)
	}
	agent["description"] = "edited by the user after setup"
	if data, err = json.MarshalIndent(agent, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// prepare-rollback --to-version 1.0.5 (only Windows converts Kiro).
	if converter, ok := connector.Connector(kiro).(connector.HookRollbackConverter); ok {
		target := opts
		target.RollbackTargetVersion = "1.0.5"
		if _, err := converter.ConvertHooksForRollback(target); err != nil {
			t.Fatalf("prepare-rollback: %v", err)
		}
	}
	left := kiroHookCommandsUnder(t, kiroHome)
	if len(left) == 0 {
		t.Fatal("no DefenseClaw Kiro hook before the swap; this test checks nothing")
	}
	// The swap: the newer data goes to previous/data, and the restored
	// install's data folder never set Kiro up.
	if err := os.Rename(dataDir, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, dataDir, "codex")()

	stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--connector", "kiro", "--rollback-backups-dir", saved)
	if exitCode != 0 {
		t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	after := kiroHookCommandsUnder(t, kiroHome)
	for command, path := range left {
		if _, ok := after[command]; ok {
			t.Errorf("the DefenseClaw Kiro hook %q stayed in %s after the rollback (prune: stdout=%q stderr=%q)", command, path, stdout, stderr)
		}
	}
}
