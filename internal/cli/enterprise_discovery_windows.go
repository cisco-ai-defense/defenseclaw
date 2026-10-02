//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/spf13/cobra"

func init() {
	enterpriseWindowsCmd.AddCommand(newWindowsDiscoveryCommand())
}

// pinEnterpriseDiscoveryEnv points an elevated administrator's (or
// LocalSystem's) discovery view at the standalone managed deployment; a
// standard account cannot read its config or gateway token.
func pinEnterpriseDiscoveryEnv() error {
	return pinManagedAdministratorEnvironment(
		"enterprise windows discovery",
		"the AI Discovery inventory of a managed computer can be read only from an elevated Administrator prompt or by the MDM agent",
	)
}

// newWindowsDiscoveryCommand is `enterprise windows discovery`, the Windows
// form of `enterprise linux|macos discovery` (GAP-1964).
func newWindowsDiscoveryCommand() *cobra.Command {
	var user string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "discovery",
		Short: "Show AI Discovery per user profile and the runtime discovery planes (read-only)",
		Long: `Show the AI Discovery inventory the gateway service found in each user
profile: AI agents and apps, skills, MCP servers, plugins and running AI
processes, grouped by the account each was found in. It reads the local
gateway's report and changes nothing.

It then shows runtime discovery (ai_discovery.runtime): each plane
(inference heartbeat, shadow egress, agent actions) with its state, the
last poll and the scored findings. Run it from an elevated Administrator
prompt, or as LocalSystem from an MDM script.

The inventory exists only while ai_discovery.enabled is true in the
deployment config. Skills and MCP servers are inventoried here; a managed
deployment does not run the skill or MCP scanners.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtimeCommand = cmd
			return writeWindowsEnterpriseDiscovery(cmd.OutOrStdout(), user, asJSON)
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "list one account's signals (account name or SID)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print every record as JSON")
	return cmd
}
