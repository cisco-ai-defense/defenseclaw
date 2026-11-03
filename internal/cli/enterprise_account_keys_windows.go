// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func runEnterpriseAccountKeys(cmd *cobra.Command) error {
	if !windowsEnterpriseIsElevated() {
		return secretFailed("not_elevated", windowsSecretExitFailure, errors.New("the account join keys require an elevated administrator prompt"))
	}
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return secretFailed("change_failed", windowsSecretExitFailure, err)
	}
	cfg, err := loadWindowsEnterpriseStandaloneConfig("")
	if err != nil {
		return secretFailed("change_failed", windowsSecretExitFailure, err)
	}
	return printEnterpriseAccountKeys(cmd.OutOrStdout(), windowsAccountJoinReport(cfg, layout))
}
