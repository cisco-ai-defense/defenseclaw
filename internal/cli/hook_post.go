// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(hookcli.NewHookPostCmd(), newHookVerifyConnectedCmd())
}

// newHookVerifyConnectedCmd builds the hidden hook-verify-connected command of
// the gateway binary.
func newHookVerifyConnectedCmd() *cobra.Command {
	var local, remote, managedService string
	verify := &cobra.Command{
		Use:         "hook-verify-connected",
		Hidden:      true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if managedService != "" {
				return hookexec.VerifyManagedConnectedTuple(local, remote, managedService)
			}
			return hookexec.VerifyPerUserConnectedTuple(local, remote)
		},
	}
	verify.Flags().StringVar(&local, "local", "", "connected client endpoint")
	verify.Flags().StringVar(&remote, "remote", "", "connected gateway endpoint")
	verify.Flags().StringVar(&managedService, "managed-service", "", "protected gateway service identity")
	_ = verify.MarkFlagRequired("local")
	_ = verify.MarkFlagRequired("remote")
	return verify
}
