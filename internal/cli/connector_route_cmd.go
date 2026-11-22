// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// connectorRouteRestoreCmd puts back the agent model settings that a
// route-only render replaced (DESIGN 7.4, 7.5, 15.9). It needs no running
// gateway, so routing disable, uninstall and rollback restore direct model
// access even during a gateway outage.
var connectorRouteRestoreCmd = &cobra.Command{
	Use:   "route-restore",
	Short: "Restore the agent model settings that route-only mode replaced",
	Long: `Restore the model base URL and provider settings that route-only mode
wrote into the agent configuration (Claude Code settings.json env, Codex
config.toml provider). Works with the gateway stopped. A connector with
nothing rendered is left untouched.`,
	Args: cobra.NoArgs,
	RunE: runConnectorRouteRestore,
}

var connectorRouteRestoreAll bool

func init() {
	connectorRouteRestoreCmd.Flags().BoolVar(&connectorRouteRestoreAll, "all", false,
		"Restore every connector that supports route-only mode")
	connectorCmd.AddCommand(connectorRouteRestoreCmd)
}

func runConnectorRouteRestore(cmd *cobra.Command, _ []string) error {
	dataDir := resolveConnectorDataDir()
	if dataDir == "" {
		return fmt.Errorf("connector route-restore: no data directory configured (set --data-dir or run defenseclaw init)")
	}
	names := []string{resolveActiveConnectorName(dataDir)}
	if connectorRouteRestoreAll {
		names = []string{"claudecode", "codex"}
	}
	reg := newConnectorRegistryWithPlugins()
	opts := resolveConnectorOpts(dataDir)
	results := map[string]string{}
	var firstErr error
	for _, name := range names {
		conn, ok := reg.Get(name)
		rc, routable := conn.(connector.RouteOnlyConnector)
		if !ok || !routable {
			results[name] = "not supported"
			continue
		}
		restore, err := bindConnectorLifecycleConfigHome(name)
		if err != nil {
			return fmt.Errorf("connector route-restore: %w", err)
		}
		err = rc.ApplyRouteOnly(opts, nil)
		restore()
		if err != nil {
			results[name] = "failed: " + err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("connector %s route-restore: %w", name, err)
			}
			continue
		}
		results[name] = "restored"
	}
	if connectorFlagJSON {
		raw, _ := json.Marshal(map[string]any{"route_restore": results})
		fmt.Fprintln(cmd.OutOrStdout(), string(raw))
	} else {
		for _, name := range names {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", name, results[name])
		}
	}
	return firstErr
}
