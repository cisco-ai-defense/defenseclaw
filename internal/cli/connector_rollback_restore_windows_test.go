// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestConnectorPrepareRollbackRestoreKeepsStoppedUnselectedLifecycleState(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, dataDir, "codex")()
	previousRestore := connectorRollbackRestore
	connectorRollbackRestore = true
	t.Cleanup(func() { connectorRollbackRestore = previousRestore })
	connectorFlagJSON = true
	settingsPath := filepath.Join(root, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previousSettings := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previousSettings })
	launcher := filepath.Join(dataDir, "bin", "defenseclaw-hook.exe")
	t.Cleanup(connector.PinNativeHookExecutableForTest(launcher))
	args := []string{"/d", "/c", "if", "exist", launcher, "(", launcher, "hook", "--connector", "claudecode", ")", "else", "(", "echo"}
	args = append(args, strings.Fields("DefenseClaw blocked this: its Claude Code hook launcher is missing. Run the DefenseClaw installer again to repair it.")...)
	args = append(args, "1>&2", "&", "exit", "/b", "2", ")")
	original, err := json.MarshalIndent(map[string]any{"foreign": "preserve", "hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command",
			"command": filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "args": args}}}}}}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.yaml", "active_connector.json", "agent_selection.json"} {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte("operator-owned-existing-state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := connector.NewClaudeCodeConnector().ConvertHooksForRollback(connector.SetupOpts{DataDir: dataDir, HookExecutable: launcher}); err != nil || count != 1 {
		t.Fatalf("converter = %d, %v", count, err)
	}
	var out, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	if err := runConnectorPrepareRollback(cmd, nil); err != nil {
		t.Fatalf("restore CLI: %v; stdout=%s stderr=%s", err, &out, &stderr)
	}
	var result struct {
		OK       bool           `json:"ok"`
		Restored map[string]int `json:"restored"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.OK || result.Restored["claudecode"] != 1 {
		t.Fatalf("restore response = %s, %v", &out, err)
	}
	if after, err := os.ReadFile(settingsPath); err != nil || !bytes.Equal(after, original) {
		t.Fatalf("original settings not restored exactly: %v", err)
	}
	for _, name := range []string{"config.yaml", "active_connector.json", "agent_selection.json"} {
		if after, err := os.ReadFile(filepath.Join(dataDir, name)); err != nil || string(after) != "operator-owned-existing-state" {
			t.Fatalf("restore mutated %s: %v", name, err)
		}
	}
	for _, name := range []string{"gateway.pid", "gateway.token", "api-token", "hook-api-token", "connector-token-claudecode"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); !os.IsNotExist(err) {
			t.Fatalf("restore created runtime/credential state %s: %v", name, err)
		}
	}
}

func TestConnectorPrepareRollbackRestoreCapabilityVisible(t *testing.T) {
	flag := connectorPrepareRollbackCmd.Flags().Lookup("restore")
	if flag == nil || flag.Hidden || !strings.Contains(connectorPrepareRollbackCmd.UsageString(), "--restore") {
		t.Fatal("current reader must advertise visible --restore capability to the installer")
	}
}
