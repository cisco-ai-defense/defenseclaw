// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/spf13/cobra"

// explainOwnGuardrailProfile is Linux and macOS only: a Windows managed
// computer's identity views are for an elevated Administrator prompt.
func explainOwnGuardrailProfile(cmd *cobra.Command, _, _, _ string, refusal, _ error, asJSON bool) error {
	return managedAdminViewRefusal(cmd, refusal, asJSON)
}

// newLauncherGuardrailCommand is nil: Windows has no launcher.
func newLauncherGuardrailCommand() *cobra.Command { return nil }
