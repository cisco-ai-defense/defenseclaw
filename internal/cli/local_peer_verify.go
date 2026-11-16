// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/spf13/cobra"
)

func init() {
	var local, remote string
	command := &cobra.Command{
		Use:         "local-peer-verify-connected",
		Hidden:      true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return hookexec.VerifyLocalConnectedTuple(local, remote)
		},
	}
	command.Flags().StringVar(&local, "local", "", "connected client endpoint")
	command.Flags().StringVar(&remote, "remote", "", "connected local-service endpoint")
	_ = command.MarkFlagRequired("local")
	_ = command.MarkFlagRequired("remote")
	rootCmd.AddCommand(command)
}
