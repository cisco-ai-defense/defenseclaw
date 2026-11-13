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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

var connectorOpenClawExportDir string

var connectorOpenClawCmd = &cobra.Command{
	Use:   "openclaw",
	Short: "OpenClaw plugin checks and the administrator-installed plugin",
}

var connectorOpenClawPreflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Check that OpenClaw setup can change the files it needs, without changing any",
	Long: `Check, before setup or an upgrade changes anything, that this account owns
and may write the OpenClaw home, openclaw.json and the managed plugin folder,
or, with connectors.openclaw.plugin_install external, that the
administrator-installed plugin is protected and matches this build.

Exit codes:
  0   setup can proceed
  1   setup would fail; the reason and the fix are printed to stderr`,
	Annotations: map[string]string{auditOptionalAnnotation: "true"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		dataDir := resolveConnectorDataDir()
		opts := resolveConnectorOptsFor(dataDir, "openclaw")
		if err := connector.NewOpenClawConnector().OpenClawPreflight(opts); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "openclaw preflight: ok")
		return nil
	},
}

var connectorOpenClawExportCmd = &cobra.Command{
	Use:   "export-plugin --dir <folder>/defenseclaw",
	Short: "Write the OpenClaw plugin of this build into a folder for an administrator install",
	Long: `Write the DefenseClaw OpenClaw plugin embedded in this build into --dir,
a new or empty folder named defenseclaw. Run it as an administrator, keep the
folder owned by root (Administrators on Windows) and not writable by others,
then set connectors.openclaw.plugin_install external and
connectors.openclaw.plugin_dir to it. Run it again after every DefenseClaw
upgrade: setup refuses a plugin that does not match the gateway.`,
	// Run by an administrator who usually has no DefenseClaw config of their
	// own: it needs none, so it loads none (rel-1-0-10 GAP-0074).
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := connector.ExportOpenClawPlugin(connectorOpenClawExportDir); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote the OpenClaw plugin to %s\nnext: defenseclaw config set connectors.openclaw.plugin_dir %s\n      defenseclaw config set connectors.openclaw.plugin_install external\n",
			connectorOpenClawExportDir, connectorOpenClawExportDir)
		return nil
	},
}

func init() {
	connectorOpenClawExportCmd.Flags().StringVar(&connectorOpenClawExportDir, "dir", "", "new or empty folder named defenseclaw")
	_ = connectorOpenClawExportCmd.MarkFlagRequired("dir")
	connectorOpenClawCmd.AddCommand(connectorOpenClawPreflightCmd)
	connectorOpenClawCmd.AddCommand(connectorOpenClawExportCmd)
	connectorCmd.AddCommand(connectorOpenClawCmd)
}
