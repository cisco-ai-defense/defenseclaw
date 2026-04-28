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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// connectorCmd is the parent for low-level connector lifecycle subcommands
// exposed via the gateway binary. These commands intentionally bypass the
// interactive `defenseclaw setup` flow and operate directly on a single
// connector implementation. They exist so that operators (and the Python
// `defenseclaw uninstall` flow) have a deterministic way to:
//
//   - Tear down the configuration patches that a connector applied
//     (`teardown`).
//   - Verify that no DefenseClaw residue remains in the agent framework's
//     config (`verify`).
//   - Inspect which pristine backups the gateway has on disk so that they
//     can be restored or rotated out (`list-backups`).
var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "Inspect and manage individual connector lifecycle state",
	Long: `Low-level connector lifecycle commands.

These subcommands operate on a single connector adapter (openclaw, codex,
claudecode, zeptoclaw, or any plugin connector) and intentionally bypass
the interactive 'defenseclaw setup' flow. They are primarily intended for
the 'defenseclaw uninstall' flow and for operator debugging when a
connector handoff (S7) leaves residual state behind.

Each subcommand accepts an optional --connector flag. When omitted, the
active connector is resolved in this order:

  1. <data-dir>/active_connector.json (written by the sidecar after a
     successful connector boot).
  2. guardrail.connector from defenseclaw.yaml.
  3. "openclaw" (legacy default).
`,
}

var (
	connectorFlagName    string
	connectorFlagJSON    bool
	connectorFlagDataDir string
)

// connectorExit is the indirection used in place of os.Exit so tests can
// observe the exit code without terminating the test binary. Production
// code paths leave this at the default (real os.Exit).
var connectorExit = os.Exit

var connectorTeardownCmd = &cobra.Command{
	Use:   "teardown",
	Short: "Run the active connector's Teardown (remove its config patches)",
	Long: `Tear down the named connector.

Calls Connector.Teardown(opts) which is responsible for:
  - Restoring the agent framework's config from its pristine backup.
  - Removing any hook scripts the connector wrote into ~/.defenseclaw.
  - Clearing any environment shims the connector installed.

This subcommand does NOT touch the sidecar's own systemd unit, the
gateway token, or the audit DB. It is the idempotent inverse of
Connector.Setup() for a single connector.`,
	RunE: runConnectorTeardown,
}

var connectorVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify that the connector left no residual state behind",
	Long: `Run Connector.VerifyClean() for the named connector.

VerifyClean returns nil when the agent framework's configuration is free
of DefenseClaw artifacts (hooks, env files, config patches, shims) and
returns a descriptive error listing residual artifacts otherwise. This is
the same check the sidecar runs before swapping connectors, so it is the
canonical way to answer "did teardown actually work?".

Exit codes:
  0   connector is clean
  1   connector has residual state (details printed to stderr)
  2   connector unknown / config error`,
	RunE: runConnectorVerify,
}

var connectorListBackupsCmd = &cobra.Command{
	Use:   "list-backups",
	Short: "List pristine connector backups stored under the data directory",
	Long: `Inspect the data directory and list every connector pristine backup
that the gateway has written.

These backups are created by Connector.Setup() before the gateway patches
the agent framework's config. They are the rollback point that
'connector teardown' uses, so listing them is the safest way to check
whether 'defenseclaw uninstall' will be able to restore the user's
original configuration.

The default output is a human-readable table:

  CONNECTOR    PATH                                              SIZE
  codex        /home/u/.defenseclaw/codex_backup.json            1234

Pass --json for a structured payload suitable for piping into 'jq'.`,
	RunE: runConnectorListBackups,
}

func init() {
	connectorCmd.PersistentFlags().StringVar(&connectorFlagName, "connector", "",
		"Connector name (defaults to the active connector resolved from active_connector.json / guardrail.connector / openclaw)")
	connectorCmd.PersistentFlags().BoolVar(&connectorFlagJSON, "json", false,
		"Emit machine-readable JSON instead of the human-readable view")
	connectorCmd.PersistentFlags().StringVar(&connectorFlagDataDir, "data-dir", "",
		"Override the data directory (defaults to cfg.DataDir)")

	connectorCmd.AddCommand(connectorTeardownCmd)
	connectorCmd.AddCommand(connectorVerifyCmd)
	connectorCmd.AddCommand(connectorListBackupsCmd)

	rootCmd.AddCommand(connectorCmd)
}

// resolveActiveConnectorName returns the connector name to operate on for
// teardown/verify, honouring --connector first, then the on-disk active
// connector marker, then guardrail.connector, then "openclaw".
func resolveActiveConnectorName(dataDir string) string {
	if name := strings.TrimSpace(connectorFlagName); name != "" {
		return strings.ToLower(name)
	}
	if dataDir != "" {
		if name := strings.TrimSpace(connector.LoadActiveConnector(dataDir)); name != "" {
			return strings.ToLower(name)
		}
	}
	if cfg != nil {
		if name := strings.TrimSpace(cfg.Guardrail.Connector); name != "" {
			return strings.ToLower(name)
		}
	}
	return "openclaw"
}

// resolveConnectorDataDir returns the data directory to inspect.
// Honours --data-dir first, then cfg.DataDir, then the package default.
// The data directory is treated as a path that the gateway already trusts
// (it is provided by the operator via flag/config and is not derived from
// untrusted user input crossing a trust boundary).
func resolveConnectorDataDir() string {
	if d := strings.TrimSpace(connectorFlagDataDir); d != "" {
		return d
	}
	if cfg != nil && cfg.DataDir != "" {
		return cfg.DataDir
	}
	return ""
}

// resolveConnectorOpts builds the SetupOpts used by Teardown/VerifyClean.
// APIToken / ProxyAddr / APIAddr are filled in best-effort from cfg —
// teardown does not need them, but VerifyClean for some connectors checks
// that env files no longer reference the proxy address, so populating
// them mirrors what the sidecar would pass at boot.
func resolveConnectorOpts(dataDir string) connector.SetupOpts {
	opts := connector.SetupOpts{
		DataDir:     dataDir,
		Interactive: false,
	}
	if cfg == nil {
		return opts
	}
	// Bind addresses are best-effort: VerifyClean only uses them as
	// substring needles for residue detection.
	if cfg.Gateway.APIPort != 0 {
		opts.APIAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Gateway.APIPort)
	}
	if cfg.Guardrail.Port != 0 {
		opts.ProxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Guardrail.Port)
	}
	return opts
}

func runConnectorTeardown(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector teardown: no data directory configured (set --data-dir or run 'defenseclaw init')")
	}
	name := resolveActiveConnectorName(dataDir)

	reg := connector.NewDefaultRegistry()
	conn, ok := reg.Get(name)
	if !ok {
		return fmt.Errorf("connector teardown: unknown connector %q (known: %s)",
			name, strings.Join(reg.Names(), ", "))
	}

	opts := resolveConnectorOpts(dataDir)
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if err := conn.Teardown(ctx, opts); err != nil {
		if connectorFlagJSON {
			payload := map[string]any{
				"connector": name,
				"action":    "teardown",
				"ok":        false,
				"error":     err.Error(),
			}
			_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
			return fmt.Errorf("connector teardown failed")
		}
		return fmt.Errorf("connector %s teardown: %w", name, err)
	}

	if connectorFlagJSON {
		payload := map[string]any{
			"connector": name,
			"action":    "teardown",
			"ok":        true,
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "[ok] %s teardown complete\n", name)
	return nil
}

func runConnectorVerify(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector verify: no data directory configured (set --data-dir or run 'defenseclaw init')")
	}
	name := resolveActiveConnectorName(dataDir)

	reg := connector.NewDefaultRegistry()
	conn, ok := reg.Get(name)
	if !ok {
		// Map "unknown connector" to exit code 2 (config error), distinct
		// from "connector dirty" (exit 1). Cobra surfaces RunE errors as
		// exit 1 by default, so we need to bypass cobra and call os.Exit.
		fmt.Fprintf(cmd.ErrOrStderr(), "connector verify: unknown connector %q (known: %s)\n",
			name, strings.Join(reg.Names(), ", "))
		connectorExit(2)
		return nil
	}

	opts := resolveConnectorOpts(dataDir)
	verifyErr := conn.VerifyClean(opts)

	if connectorFlagJSON {
		payload := map[string]any{
			"connector": name,
			"action":    "verify",
			"clean":     verifyErr == nil,
		}
		if verifyErr != nil {
			payload["residue"] = verifyErr.Error()
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
		if verifyErr != nil {
			connectorExit(1)
		}
		return nil
	}

	if verifyErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "[dirty] %s: %v\n", name, verifyErr)
		connectorExit(1)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "[clean] %s: no residual DefenseClaw state detected\n", name)
	return nil
}

// connectorBackup is one entry returned by `connector list-backups`.
type connectorBackup struct {
	Connector string `json:"connector"`
	Path      string `json:"path"`
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"size_bytes"`
}

// knownConnectorBackups maps backup filename → connector name. Centralised
// here so that adding a new built-in connector is a one-line change.
var knownConnectorBackups = map[string]string{
	"zeptoclaw_backup.json":  "zeptoclaw",
	"claudecode_backup.json": "claudecode",
	"codex_backup.json":      "codex",
	// OpenClaw stores its backup as <claw_config>.pristine *next to* the
	// claw config file, not under the data directory. discoverOpenClawBackup
	// handles that case below.
}

// discoverOpenClawBackup checks for the OpenClaw pristine backup, which
// lives at the same path as the claw config file with a `.pristine`
// suffix. Returns nil when the backup is missing or unreadable.
func discoverOpenClawBackup() *connectorBackup {
	if cfg == nil || cfg.Claw.ConfigFile == "" {
		return nil
	}
	path := cfg.Claw.ConfigFile + ".pristine"
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	return &connectorBackup{
		Connector: "openclaw",
		Path:      path,
		Filename:  filepath.Base(path),
		SizeBytes: info.Size(),
	}
}

func runConnectorListBackups(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector list-backups: no data directory configured (set --data-dir or run 'defenseclaw init')")
	}

	backups := make([]connectorBackup, 0, len(knownConnectorBackups)+1)

	for filename, name := range knownConnectorBackups {
		full := filepath.Join(dataDir, filename)
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			continue
		}
		backups = append(backups, connectorBackup{
			Connector: name,
			Path:      full,
			Filename:  filename,
			SizeBytes: info.Size(),
		})
	}

	if oc := discoverOpenClawBackup(); oc != nil {
		backups = append(backups, *oc)
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Connector < backups[j].Connector
	})

	if connectorFlagJSON {
		payload := map[string]any{
			"data_dir": dataDir,
			"count":    len(backups),
			"backups":  backups,
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(payload)
	}

	out := cmd.OutOrStdout()
	if len(backups) == 0 {
		fmt.Fprintf(out, "no connector backups found under %s\n", dataDir)
		return nil
	}
	fmt.Fprintf(out, "%-12s  %-60s  %s\n", "CONNECTOR", "PATH", "SIZE")
	for _, b := range backups {
		fmt.Fprintf(out, "%-12s  %-60s  %d\n", b.Connector, b.Path, b.SizeBytes)
	}
	return nil
}
