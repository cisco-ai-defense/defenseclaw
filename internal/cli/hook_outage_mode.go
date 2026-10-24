// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hookOutageFailModeNow is the gateway-outage mode the config on disk gives
// connectorName's per-user hooks now (config.HookOutageFailMode of its policy
// tier): "open" only when this release loads the config, the install is
// neither managed nor Secure Client, and the connector's rule pack is not
// strict. Every other case is "closed".
//
// A per-user hook asks it only when its runtime record (hooks/.hookcfg*, a
// plugin's baked mode) would let an outage run. The record is what the
// gateway or the last refresh wrote, and a rule-pack change made since (strict
// selected while the gateway is stopped, or with hook_self_heal off) has not
// reached it, so the record alone cannot open a call.
func hookOutageFailModeNow(connectorName string) string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if name == "" {
		return "closed"
	}
	loaded, err := config.LoadFromFile(config.ConfigPath())
	if err != nil || loaded == nil || managed.IsManagedEnterprise(loaded.DeploymentMode) || loaded.SecureClientIntegration() {
		return "closed"
	}
	if loaded.EffectiveHookOutageFailModeForConnector(name) == "open" {
		return "open"
	}
	return "closed"
}

func init() {
	var connectorName string
	cmd := &cobra.Command{
		Use:    "hook-outage-mode",
		Short:  "Print the gateway-outage mode the config gives a per-user connector's hooks now",
		Hidden: true,
		// A hook runs it while the gateway is down: no daemon bootstrap,
		// no audit store, only a read of config.yaml.
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), hookOutageFailModeNow(connectorName))
			return err
		},
	}
	cmd.Flags().StringVar(&connectorName, "connector", "", "connector name")
	_ = cmd.MarkFlagRequired("connector")
	rootCmd.AddCommand(cmd)
}
