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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// connectorCoworkPluginCmd prints the hooks/hooks.json of the DefenseClaw
// Cowork account plugin, which `defenseclaw setup cowork` zips. The Go side
// renders it so the plugin runs exactly the Claude Code handler Setup writes
// (connector.CoworkPluginHooks); Python only packages it.
var connectorCoworkPluginCmd = &cobra.Command{
	Use:   "cowork-plugin",
	Short: "Print the hooks.json of the DefenseClaw Cowork plugin (run by setup cowork)",
	Long: `Print, as JSON, the hooks/hooks.json document of the DefenseClaw plugin that
'defenseclaw setup cowork' builds for Claude Cowork. Its handlers run the
Claude Code connector's hook, so the Claude Code connector must be set up.
It changes nothing.

Exit codes:
  0   the document is printed on stdout
  1   refused (managed install, or the Claude Code connector is not set up);
      with --json stdout holds {"error": ..., "reason": ...}
  2   no data directory configured`,
	Hidden:      true,
	Args:        cobra.NoArgs,
	Annotations: map[string]string{auditOptionalAnnotation: "true"},
	RunE:        runConnectorCoworkPlugin,
}

func init() {
	connectorCmd.AddCommand(connectorCoworkPluginCmd)
}

func runConnectorCoworkPlugin(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "connector cowork-plugin: no data directory configured (set --data-dir or run 'defenseclaw init')")
		connectorExit(2)
		return nil
	}
	opts := resolveConnectorOptsFor(dataDir, "claudecode")
	if cfg != nil {
		opts.ManagedEnterprise = managed.IsManagedEnterprise(cfg.DeploymentMode)
	}
	document, err := connector.CoworkPluginHooks(opts)
	if err != nil {
		reason := "refused"
		if errors.Is(err, connector.ErrCoworkClaudeCodeNotSetUp) {
			reason = "claudecode_not_set_up"
		} else if opts.ManagedEnterprise {
			reason = "managed"
		}
		if connectorFlagJSON {
			_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"error": err.Error(), "reason": reason})
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "connector cowork-plugin: %v\n", err)
		}
		connectorExit(1)
		return nil
	}
	_, err = cmd.OutOrStdout().Write(append(document, '\n'))
	return err
}
