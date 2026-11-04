// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// TestConnectorClaudeDesktopEngineExitCodes pins what Windows per-user setup
// reads (GAP-0039): exit 0 with the build, exit 1 with reason not_found.
func TestConnectorClaudeDesktopEngineExitCodes(t *testing.T) {
	savedLookup, savedExit := claudeDesktopEngineLookup, connectorExit
	t.Cleanup(func() { claudeDesktopEngineLookup, connectorExit = savedLookup, savedExit })
	run := func(build enterprisehooks.ClaudeDesktopEngineBuild) (int, map[string]any) {
		t.Helper()
		claudeDesktopEngineLookup = func(context.Context, string) enterprisehooks.ClaudeDesktopEngineBuild { return build }
		code := 0
		connectorExit = func(exit int) { code = exit }
		var out bytes.Buffer
		cmd := &cobra.Command{Use: "claude-desktop-engine"}
		cmd.SetOut(&out)
		if err := runConnectorClaudeDesktopEngine(cmd, nil); err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout %q: %v", out.String(), err)
		}
		return code, doc
	}
	code, doc := run(enterprisehooks.ClaudeDesktopEngineBuild{Version: "2.1.317", EngineDir: `C:\u\Claude-3p\claude-code`, Executable: `C:\u\Claude-3p\claude-code\2.1.317\b\claude.exe`})
	if code != 0 || doc["version"] != "2.1.317" || doc["executable"] != `C:\u\Claude-3p\claude-code\2.1.317\b\claude.exe` {
		t.Fatalf("verified: exit %d %v", code, doc)
	}
	code, doc = run(enterprisehooks.ClaudeDesktopEngineBuild{Unverified: "Claude Desktop engine 2.1.317: claude.exe is not signed"})
	if code != 1 || doc["reason"] != "not_found" || doc["unverified"] != "Claude Desktop engine 2.1.317: claude.exe is not signed" {
		t.Fatalf("none: exit %d %v", code, doc)
	}
}

// cowork-1-0-8 GAP-0043: the probe ran the root bootstrap, so an account
// without config.yaml got "failed to load config" (exit 1, no JSON) and
// setup told the user to update DefenseClaw. It skips the bootstrap: the
// root pre-run loads nothing for it, on an empty data directory too.
func TestConnectorClaudeDesktopEngineNeedsNoConfig(t *testing.T) {
	if connectorClaudeDesktopEngineCmd.Annotations["defenseclaw.skip-daemon-bootstrap"] != "true" {
		t.Fatal("claude-desktop-engine must skip the daemon bootstrap (no config.yaml load)")
	}
	home := t.TempDir()
	data := filepath.Join(home, ".defenseclaw")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("DEFENSECLAW_HOME", data)
	savedCfg := cfg
	t.Cleanup(func() { cfg = savedCfg })
	cfg = nil
	if err := rootPersistentPreRunE(connectorClaudeDesktopEngineCmd, nil); err != nil {
		t.Fatalf("root pre-run with no config.yaml: %v", err)
	}
	if cfg != nil {
		t.Fatal("root pre-run loaded a config for the engine probe")
	}
	if _, err := os.Stat(filepath.Join(data, "audit.db")); !os.IsNotExist(err) {
		t.Fatalf("the probe created DefenseClaw state (audit.db): %v", err)
	}
}
