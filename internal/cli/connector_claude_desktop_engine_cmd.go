// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// connectorClaudeDesktopEngineCmd prints the Claude Desktop engine build of
// the calling account that verifies as enrolment verifies it (code signature
// on macOS, Authenticode on Windows, an executable on Linux). Per-user setup
// on Windows runs it to bind Claude Desktop's engine as the Claude Code
// executable of an account without the claude CLI (cowork-1-0-8 GAP-0039):
// Python has no signature check of its own.
var connectorClaudeDesktopEngineCmd = &cobra.Command{
	Use:   "claude-desktop-engine",
	Short: "Print this account's verified Claude Desktop Claude Code engine (run by setup)",
	Long: `Print, as JSON, the newest Claude Code engine build Claude Desktop keeps for
this account whose code signature verifies: {"version", "engine_dir",
"executable" (Windows)}. It reads files and runs nothing from them; it
changes nothing.

Exit codes:
  0   a verified build is printed on stdout
  1   no build verifies; stdout holds {"error": ..., "reason": "not_found",
      "unverified": ...}`,
	Hidden: true,
	Args:   cobra.NoArgs,
	// It needs only the account's home and the Claude Desktop data folders:
	// no config.yaml, audit store or daemon registration. An account without
	// a config (setup before init) got "failed to load config" instead of
	// its JSON answer (cowork-1-0-8 GAP-0043).
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE:        runConnectorClaudeDesktopEngine,
}

func init() {
	connectorCmd.AddCommand(connectorClaudeDesktopEngineCmd)
}

// claudeDesktopEngineLookup is enterprisehooks.ClaudeDesktopEngine; tests
// replace it.
var claudeDesktopEngineLookup = enterprisehooks.ClaudeDesktopEngine

func runConnectorClaudeDesktopEngine(cmd *cobra.Command, _ []string) error {
	home, err := os.UserHomeDir()
	build := enterprisehooks.ClaudeDesktopEngineBuild{}
	if err == nil {
		build = claudeDesktopEngineLookup(context.Background(), home)
	}
	if build.Version == "" {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{
			"error":      "no Claude Desktop engine build of this account verifies",
			"reason":     "not_found",
			"unverified": build.Unverified,
		})
		connectorExit(1)
		return nil
	}
	if err := json.NewEncoder(cmd.OutOrStdout()).Encode(build); err != nil {
		return fmt.Errorf("connector claude-desktop-engine: %w", err)
	}
	return nil
}
